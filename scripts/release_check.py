"""Build reproducible release artifacts and inspect their contents.

Usage: .venv/bin/python scripts/release_check.py --receipt docs/_reset/release.json
The check builds twice, compares artifact hashes, verifies wheel RECORD hashes,
rejects unsafe archive members, exports a CycloneDX SBOM, and optionally checks
an already installed wheel in a clean interpreter. It does not publish.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
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
        raise SystemExit(f"command failed: {' '.join(args)}\n{result.stderr.strip()}")
    return result.stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifacts(directory):
    return sorted(path for path in Path(directory).iterdir()
                  if path.suffix in (".whl", ".gz"))


def check_names(names):
    for name in names:
        normalized = name.replace("\\", "/")
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
        record = next(name for name in names if name.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
        for name, hash_value, size in rows:
            if not hash_value:
                continue
            algorithm, encoded = hash_value.split("=", 1)
            if algorithm != "sha256":
                raise SystemExit(f"unsupported RECORD hash: {hash_value}")
            expected = base64.urlsafe_b64encode(
                hashlib.sha256(archive.read(name)).digest()).rstrip(b"=").decode("ascii")
            if encoded != expected:
                raise SystemExit(f"wheel RECORD hash mismatch: {name}")
            if size and int(size) != len(archive.read(name)):
                raise SystemExit(f"wheel RECORD size mismatch: {name}")
        metadata = next(name for name in names if name.endswith(".dist-info/METADATA"))
        entry = next(name for name in names if name.endswith(".dist-info/entry_points.txt"))
        package = [name for name in names if name.startswith("cryptalis/") and name.endswith(".py")]
        if not package:
            raise SystemExit("wheel contains no cryptalis package modules")
        if not any(name.endswith("/licenses/LICENSE") for name in names):
            raise SystemExit("wheel does not contain the license file")
        if ENTRY_POINT not in archive.read(entry).decode("utf-8"):
            raise SystemExit("wheel entry point is missing")
        return {"members": len(names), "modules": len(package),
                "metadata": metadata, "record": record}


def inspect_sdist(path):
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
        check_names(names)
        package = [name for name in names if "/src/cryptalis/" in name and name.endswith(".py")]
        if not package:
            raise SystemExit("sdist contains no cryptalis package modules")
        required = ("pyproject.toml", "README.md", "LICENSE")
        if not all(any(name.endswith("/" + item) for name in names) for item in required):
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
             ROOT / "scripts" / "release_check.py"]
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
            probe = (
                "import pathlib, cryptalis, runpy, sys\n"
                "root = pathlib.Path(sys.argv[1]).resolve()\n"
                "package = pathlib.Path(cryptalis.__file__).resolve()\n"
                "assert root not in package.parents and package.parent != root\n"
                "print(package)\n")
            installed = run([str(python), "-c", probe, str(ROOT)], cwd=base)
            help_text = run([str(python), "-m", "cryptalis", "--help"], cwd=base)
            if "usage: cryptalis" not in help_text:
                raise SystemExit("installed CLI did not start")
            clean = {"package": installed.strip(), "cli": "passed"}
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
