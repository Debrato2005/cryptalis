"""Build reproducible release artifacts and inspect their contents.

Usage: .venv/bin/python scripts/release_check.py --receipt docs/_reset/release.json
The check builds twice, compares artifact hashes, verifies wheel RECORD hashes,
rejects unsafe archive members, exports a CycloneDX SBOM, and optionally checks
an already installed wheel in a clean interpreter. It does not publish.
"""
import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[1]
ENTRY_POINT = "cryptalis = cryptalis.cli:main"
FORBIDDEN_PARTS = (".pth", ".pyc", "__pycache__", ".env", ".cryptalis", ".git")
FORBIDDEN_PREFIXES = ("tests/", "docs/", "examples/", "spikes/")
NETWORK_TERMS = ("import socket", "import subprocess", "import urllib", "import http",
                 "import requests", "from socket", "from subprocess", "from urllib",
                 "from http", "from requests", "telemetry", "analytics")


def run(args, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        # Installer indexes and interpreter startup hooks can print credentials.
        # Keep the tool and status observable without relaying raw diagnostics.
        raise SystemExit(f"Release.CommandFailed: {Path(args[0]).name}; exit {result.returncode}")
    return result.stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifacts(directory):
    return sorted(path for path in Path(directory).iterdir()
                  if path.suffix in (".whl", ".gz"))


def check_names(names):
    if len(names) != len(set(names)):
        raise SystemExit("duplicate archive member")
    for name in names:
        normalized = name.rstrip("/")
        if (not normalized or "\\" in name or ":" in normalized.split("/")[0]
                or any(part in ("", ".", "..") for part in normalized.split("/"))):
            raise SystemExit(f"unsafe archive member: {name}")
        if any(part in normalized for part in FORBIDDEN_PARTS):
            raise SystemExit(f"forbidden archive member: {name}")
        if normalized.startswith(FORBIDDEN_PREFIXES):
            raise SystemExit(f"forbidden archive member: {name}")
        if normalized.startswith("/") or ".." in Path(normalized).parts:
            raise SystemExit(f"unsafe archive member: {name}")


def inspect_wheel(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        check_names(names)
        for member in archive.infolist():
            kind = stat.S_IFMT(member.external_attr >> 16)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise SystemExit(f"unsafe wheel member type: {member.filename}")
            if ((member.is_dir() and (member.file_size or kind == stat.S_IFREG))
                    or (not member.is_dir() and kind == stat.S_IFDIR)):
                raise SystemExit(f"invalid wheel directory entry: {member.filename}")
        records = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(records) != 1:
            raise SystemExit("wheel must contain exactly one RECORD")
        record = records[0]
        rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
        if any(len(row) != 3 for row in rows):
            raise SystemExit("wheel RECORD rows must have three columns")
        recorded = [row[0] for row in rows]
        files = {member.filename for member in archive.infolist() if not member.is_dir()}
        if len(recorded) != len(set(recorded)) or set(recorded) != files:
            raise SystemExit("wheel RECORD must list every file exactly once")
        for name, hash_value, size in rows:
            if name == record:
                if hash_value or size:
                    raise SystemExit("wheel RECORD cannot hash or size itself")
                continue
            if not hash_value.startswith("sha256="):
                raise SystemExit(f"wheel RECORD requires a SHA-256 hash: {name}")
            encoded = hash_value.removeprefix("sha256=")
            content = archive.read(name)
            expected = base64.urlsafe_b64encode(
                hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
            if encoded != expected:
                raise SystemExit(f"wheel RECORD hash mismatch: {name}")
            if size != str(len(content)):
                raise SystemExit(f"wheel RECORD size mismatch: {name}")
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        info = f'{project["name"].replace("-", "_")}-{project["version"]}.dist-info'
        info_roots = {part for name in names for part in name.split("/") if part.endswith(".dist-info")}
        required = {f"{info}/{name}" for name in (
            "RECORD", "METADATA", "WHEEL", "entry_points.txt", "licenses/LICENSE")}
        if info_roots != {info} or not required <= files:
            raise SystemExit("wheel distribution metadata is missing or mismatched")
        metadata, entry = f"{info}/METADATA", f"{info}/entry_points.txt"
        declared = BytesParser().parsebytes(archive.read(metadata))
        if (declared.get_all("Name") != [project["name"]]
                or declared.get_all("Version") != [project["version"]]):
            raise SystemExit("wheel project name or version does not match pyproject.toml")
        package = [name for name in names if name.startswith("cryptalis/") and name.endswith(".py")]
        if not package:
            raise SystemExit("wheel contains no cryptalis package modules")
        if ENTRY_POINT not in archive.read(entry).decode("utf-8"):
            raise SystemExit("wheel entry point is missing")
        return {"members": len(names), "modules": len(package),
                "metadata": metadata, "record": record}


def inspect_sdist(path):
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
        check_names(names)
        roots = {name.split("/", 1)[0] for name in names}
        if len(roots) != 1:
            raise SystemExit("sdist must contain exactly one root directory")
        files = []
        for member in archive.getmembers():
            if not (member.isfile() or member.isdir()):
                raise SystemExit(f"unsafe sdist member type: {member.name}")
            relative = member.name.partition("/")[2]
            if not relative:
                if member.isdir():
                    continue
                raise SystemExit("sdist files must be inside the root directory")
            check_names([relative])
            if member.isfile():
                files.append(relative)
        package = [name for name in files if name.startswith("src/cryptalis/") and name.endswith(".py")]
        if not package:
            raise SystemExit("sdist contains no cryptalis package modules")
        required = ("pyproject.toml", "README.md", "LICENSE")
        if not set(required) <= set(files):
            raise SystemExit("sdist is missing project metadata")
        return {"members": len(names), "modules": len(package)}


def inspect_source_imports(root):
    findings = []
    for path in sorted(Path(root).rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for term in NETWORK_TERMS:
            if term in text:
                findings.append({"file": str(path.relative_to(root)), "term": term})
    return findings


def build(directory):
    run(["uv", "build", "--out-dir", str(directory), "--no-build-logs"])
    return artifacts(directory)


def source_hashes():
    paths = [ROOT / "pyproject.toml", ROOT / "LICENSE", ROOT / "README.md",
             ROOT / "scripts" / "release_check.py",
             ROOT / "scripts" / "test_release_check.py"]
    paths += sorted((ROOT / "src").rglob("*.py"))
    return {str(path.relative_to(ROOT)): digest(path) for path in paths}


def copied(first, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    written = []
    for path in first:
        target = output / path.name
        shutil.copy2(path, target)
        written.append(target)
    return written


def inspect_install(python, wheel, cwd):
    # Compare installed bytes with the inspected wheel, rather than trusting the
    # installed RECORD or an unrelated working package of the same version.
    probe = '''import hashlib, importlib.metadata, json, pathlib, sys, zipfile
root, wheel = (pathlib.Path(value).resolve() for value in sys.argv[1:])
distribution = importlib.metadata.distribution("cryptalis")
site = pathlib.Path(distribution.locate_file("")).resolve()
if sys.prefix == sys.base_prefix or pathlib.Path(sys.prefix).resolve() not in site.parents:
    raise SystemExit("installed package must reside in the selected virtual environment")
with zipfile.ZipFile(wheel) as archive:
    expected = {name for name in archive.namelist() if not name.endswith("/")
                and not name.endswith(".dist-info/RECORD")}
    for name in expected:
        installed = pathlib.Path(distribution.locate_file(name))
        if (not installed.is_file() or installed.is_symlink()
                or site not in installed.resolve().parents
                or hashlib.sha256(installed.read_bytes()).digest()
                != hashlib.sha256(archive.read(name)).digest()):
            raise SystemExit("installed artifact differs from wheel: " + name)
    package_files = {str(path.relative_to(site)) for path in (site / "cryptalis").rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts}
    if package_files != {name for name in expected if name.startswith("cryptalis/")}:
        raise SystemExit("installed package contains unrecorded files")
import cryptalis
package = pathlib.Path(cryptalis.__file__).resolve()
if root in package.parents or package != (site / "cryptalis/__init__.py").resolve():
    raise SystemExit("imported package does not match the installed wheel")
print(json.dumps({"package": str(package), "verified_files": len(expected)}))
'''
    # A preexisting unchecked-hash .pyc can override byte-identical source. Use
    # a fresh cache for both checks so imports compile the verified source.
    with tempfile.TemporaryDirectory(prefix="verified-source-", dir=cwd) as cache:
        interpreter = [str(python), "-I", "-X", f"pycache_prefix={cache}"]
        installed = json.loads(run(interpreter + ["-c", probe, str(ROOT), str(wheel)], cwd=cwd))
        help_text = run(interpreter + ["-m", "cryptalis", "--help"], cwd=cwd)
    if "usage: cryptalis" not in help_text:
        raise SystemExit("installed CLI did not start")
    return dict(installed, cli="passed", wheel_sha256=digest(wheel))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--python", type=Path,
                        help="Interpreter of a clean virtual environment with the wheel installed.")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="cryptalis-release-") as temporary:
        base = Path(temporary)
        first = build(base / "first")
        second = build(base / "second")
        first_hashes = {path.name: digest(path) for path in first}
        second_hashes = {path.name: digest(path) for path in second}
        if first_hashes != second_hashes:
            raise SystemExit(f"release build is not reproducible: {first_hashes} != {second_hashes}")
        wheel = next(path for path in first if path.suffix == ".whl")
        sdist = next(path for path in first if path.suffix == ".gz")
        wheel_facts = inspect_wheel(wheel)
        sdist_facts = inspect_sdist(sdist)
        findings = inspect_source_imports(ROOT / "src" / "cryptalis")
        if findings:
            raise SystemExit(f"release source contains network/telemetry terms: {findings}")
        output = copied(first, args.output)
        sbom = Path(args.output) / "sbom.cdx.json"
        run(["uv", "export", "--format", "cyclonedx1.5", "--no-dev", "--locked",
             "--output-file", str(sbom)])
        document = json.loads(sbom.read_text(encoding="utf-8"))
        if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
            raise SystemExit("SBOM is not CycloneDX 1.5")
        components = {item["name"] for item in document.get("components", [])}
        components.add(document.get("metadata", {}).get("component", {}).get("name"))
        if not {"cryptalis", "cryptography", "psycopg", "sqlalchemy"} <= components:
            raise SystemExit("SBOM is missing a runtime component")
        checksums = Path(args.output) / "SHA256SUMS"
        lines = [f"{digest(path)}  {path.name}" for path in output]
        checksums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        clean = "NOT MEASURED"
        if args.python:
            python = args.python.expanduser().absolute()
            clean = inspect_install(python, wheel, base)
        hashes = source_hashes()
        working = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        receipt = {
            "format": "cryptalis.release-check/v1",
            "base_revision": run(["git", "rev-parse", "HEAD"]).strip(),
            "fixing_revision": "worktree-" + working[:16],
            "source_sha256": hashes,
            "dirty": bool(run(["git", "status", "--porcelain"]).strip()),
            "artifacts": {path.name: digest(path) for path in output},
            "reproducible": True,
            "wheel": wheel_facts,
            "sdist": sdist_facts,
            "sbom": {"path": sbom.name, "sha256": digest(sbom), "components": sorted(components)},
            "source_scan": {"network_or_telemetry_terms": findings},
            "clean_install": clean,
            "gate": "UNKNOWN",
        }
        if args.receipt:
            with Path(args.receipt).open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
