"""Offline artifact-integrity regressions. Run with Python, without a database."""

import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import py_compile
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import warnings
import venv
import zipfile

from release_check import ROOT, inspect_sdist, inspect_wheel
from packaging.markers import Marker
from packaging.requirements import Requirement


INFO = "cryptalis-0.1.0.dist-info"
RECORD = INFO + "/RECORD"
MODULE = "cryptalis/__init__.py"


def wheel_files(include_optional=True):
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    metadata = ("Metadata-Version: 2.4\nName: cryptalis\nVersion: 0.1.0\n"
                + "Requires-Python: " + project["requires-python"] + "\n"
                + "".join("Requires-Dist: " + dependency + "\n" for dependency in project["dependencies"]))
    if include_optional:
        for extra, dependencies in project.get("optional-dependencies", {}).items():
            metadata += "Provides-Extra: " + extra + "\n"
            for dependency in dependencies:
                requirement = Requirement(dependency)
                condition = f'extra == "{extra}"'
                requirement.marker = Marker(
                    f"({requirement.marker}) and {condition}" if requirement.marker else condition)
                metadata += "Requires-Dist: " + str(requirement) + "\n"
    return {
        MODULE: b'"""Artifact fixture."""\n',
        INFO + "/METADATA": metadata.encode(),
        INFO + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        INFO + "/entry_points.txt": b"[console_scripts]\ncryptalis = cryptalis.cli:main\n",
        INFO + "/licenses/LICENSE": b"MIT\n",
    }


def record_rows(files):
    rows = []
    for name, content in files.items():
        encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        rows.append([name, "sha256=" + encoded.decode("ascii"), str(len(content))])
    return rows + [[RECORD, "", ""]]


def write_wheel(path, files, rows, extra=()):
    output = io.StringIO(newline="")
    csv.writer(output).writerows(rows)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
            archive.writestr(RECORD, output.getvalue())
            for name, content in extra:
                archive.writestr(name, content)


def write_sdist(path, extra=()):
    root = "cryptalis-0.1.0/"
    files = {"src/cryptalis/__init__.py": b"", "pyproject.toml": b"",
             "README.md": b"", "LICENSE": b""}
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(root + name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for member in extra:
            archive.addfile(member, io.BytesIO(b""))


class ArtifactIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cryptalis-artifact-test-")
        self.addCleanup(self.temporary.cleanup)
        self.wheel = Path(self.temporary.name) / "fixture.whl"
        self.sdist = Path(self.temporary.name) / "fixture.tar.gz"

    def test_complete_archives_pass(self):
        files = wheel_files()
        write_wheel(self.wheel, files, record_rows(files))
        self.assertEqual(inspect_wheel(self.wheel)["modules"], 1)
        write_sdist(self.sdist)
        self.assertEqual(inspect_sdist(self.sdist)["modules"], 1)

    def test_wheel_python_metadata_matches_project(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        expected = "Requires-Python: " + project["requires-python"] + "\n"
        for replacement in ("", "Requires-Python: >=3.13\n", expected * 2,
                            "Requires-Python: invalid\n"):
            with self.subTest(replacement=replacement):
                files = wheel_files()
                files[INFO + "/METADATA"] = files[INFO + "/METADATA"].replace(
                    expected.encode(), replacement.encode())
                write_wheel(self.wheel, files, record_rows(files))
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_wheel_dependency_metadata_matches_project(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        expected = "Requires-Dist: " + project["dependencies"][0] + "\n"
        for replacement in ("", "Requires-Dist: cryptography==1\n", expected * 2,
                            expected.rstrip() + "; python_version < '3'\n",
                            "Requires-Dist: invalid !!!\n"):
            with self.subTest(replacement=replacement):
                files = wheel_files()
                files[INFO + "/METADATA"] = files[INFO + "/METADATA"].replace(
                    expected.encode(), replacement.encode())
                write_wheel(self.wheel, files, record_rows(files))
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_wheel_equivalent_dependency_metadata_keeps_extras(self):
        files = wheel_files()
        metadata = files[INFO + "/METADATA"].decode()
        headers = metadata.splitlines()
        dependencies = [line for line in headers if line.startswith("Requires-Dist:")]
        metadata = "\n".join(line for line in headers if not line.startswith("Requires-Dist:")) + "\n"
        metadata += "\n".join(
            line.partition(";")[0].upper() + (";" + line.partition(";")[2] if ";" in line else "")
            for line in reversed(dependencies)) + "\n"
        files[INFO + "/METADATA"] = metadata.encode()
        write_wheel(self.wheel, files, record_rows(files))
        self.assertEqual(inspect_wheel(self.wheel)["modules"], 1)
        files[INFO + "/METADATA"] = metadata.replace("[BINARY]", "").encode()
        write_wheel(self.wheel, files, record_rows(files))
        with self.assertRaises(SystemExit):
            inspect_wheel(self.wheel)

    def test_wheel_optional_dependencies_match_the_declared_extra(self):
        root = Path(self.temporary.name)
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        (root / "pyproject.toml").write_text(
            "[project]\n" + "".join(key + " = " + json.dumps(project[key]) + "\n"
                                      for key in ("name", "version", "requires-python", "dependencies"))
            + '\n[project.optional-dependencies]\nsqlmodel = ["sqlmodel==0.0.48"]\n')
        files = wheel_files(include_optional=False)
        metadata = files[INFO + "/METADATA"]
        extra = b'Provides-Extra: sqlmodel\n'
        dependency = b'Requires-Dist: sqlmodel==0.0.48; extra == "sqlmodel"\n'
        with patch("release_check.ROOT", root):
            for suffix in (extra + dependency,
                           b'Provides-Extra: SQLMODEL\nRequires-Dist: SQLMODEL==0.0.48; extra == "SQLMODEL"\n'):
                with self.subTest(valid=suffix):
                    files[INFO + "/METADATA"] = metadata + suffix
                    write_wheel(self.wheel, files, record_rows(files))
                    self.assertEqual(inspect_wheel(self.wheel)["modules"], 1)
            for suffix in (extra, dependency, extra * 2 + dependency,
                           extra + dependency * 2,
                           extra + dependency.replace(b"0.0.48", b"0.0.47"),
                           extra + dependency.replace(b'sqlmodel"', b'other"'),
                           extra + b'Requires-Dist: sqlmodel==0.0.48\n',
                           extra + dependency + b'Provides-Extra: other\n'):
                with self.subTest(invalid=suffix):
                    files[INFO + "/METADATA"] = metadata + suffix
                    write_wheel(self.wheel, files, record_rows(files))
                    with self.assertRaises(SystemExit):
                        inspect_wheel(self.wheel)

        original = "sys_platform == 'win32' or python_version < '3.14'"
        project_path = root / "pyproject.toml"
        project_path.write_text(project_path.read_text().replace(
            'sqlmodel==0.0.48', 'sqlmodel==0.0.48; ' + original))
        conditional = (b'Requires-Dist: sqlmodel==0.0.48; '
                       b'(sys_platform == "win32" or python_version < "3.14") '
                       b'and extra == "sqlmodel"\n')
        with patch("release_check.ROOT", root):
            files[INFO + "/METADATA"] = metadata + extra + conditional
            write_wheel(self.wheel, files, record_rows(files))
            self.assertEqual(inspect_wheel(self.wheel)["modules"], 1)
            files[INFO + "/METADATA"] = metadata + extra + dependency
            write_wheel(self.wheel, files, record_rows(files))
            with self.assertRaises(SystemExit):
                inspect_wheel(self.wheel)

    def test_record_cannot_omit_or_repeat_archive_files(self):
        files = wheel_files()
        complete = record_rows(files)
        variants = {
            "empty": [], "omitted module": complete[1:],
            "omitted RECORD": complete[:-1], "duplicate row": complete + [complete[0]],
            "phantom row": complete + [["absent.py", "sha256=unused", "0"]],
        }
        for label, rows in variants.items():
            with self.subTest(label=label):
                write_wheel(self.wheel, files, rows)
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_record_requires_valid_hash_and_size_for_each_file(self):
        files = wheel_files()
        for hash_value, size in (("", ""), ("", "1"), ("sha256=wrong", "1"),
                                 ("md5=wrong", "1"), (None, ""), (None, "-1"),
                                 (None, "not-an-integer"), (None, "999")):
            with self.subTest(hash_value=hash_value, size=size):
                rows = record_rows(files)
                if hash_value is not None:
                    rows[0][1] = hash_value
                rows[0][2] = size
                write_wheel(self.wheel, files, rows)
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_record_has_exactly_three_columns_and_no_self_hash(self):
        files = wheel_files()
        for replacement in ([MODULE], [MODULE, "hash", "1", "extra"],
                            [RECORD, "sha256=wrong", "1"], [RECORD, "", "1"]):
            with self.subTest(replacement=replacement):
                rows = record_rows(files)
                rows[-1 if replacement[0] == RECORD else 0] = replacement
                write_wheel(self.wheel, files, rows)
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_wheel_rejects_duplicate_members_and_symbolic_links(self):
        files = wheel_files()
        link = zipfile.ZipInfo("cryptalis/link.py")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for extra in (((MODULE, files[MODULE]),), ((link, b"/etc/passwd"),)):
            with self.subTest(extra=str(extra[0][0])):
                write_wheel(self.wheel, files, record_rows(files), extra)
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_wheel_rejects_noncanonical_paths(self):
        for name in ("/absolute.py", "../escape.py", "cryptalis/../escape.py",
                     "C:/escape.py", "cryptalis\\escape.py", "cryptalis//escape.py",
                     "cryptalis/./escape.py"):
            with self.subTest(name=name):
                files = wheel_files() | {name: b""}
                write_wheel(self.wheel, files, record_rows(files))
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_wheel_directory_entries_cannot_hide_unhashed_payloads(self):
        files = wheel_files()
        directory = zipfile.ZipInfo("cryptalis/empty/")
        directory.create_system = 3
        directory.external_attr = (stat.S_IFDIR | 0o755) << 16
        write_wheel(self.wheel, files, record_rows(files), [(directory, b"")])
        self.assertEqual(inspect_wheel(self.wheel)["modules"], 1)
        for name, content, kind in (("cryptalis/hidden/", b"unhashed", stat.S_IFDIR),
                                    ("cryptalis/file/", b"", stat.S_IFREG),
                                    ("cryptalis/directory", b"", stat.S_IFDIR)):
            with self.subTest(name=name):
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = (kind | 0o755) << 16
                write_wheel(self.wheel, files, record_rows(files), [(member, content)])
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_wheel_requires_its_own_distribution_metadata(self):
        for change in ("name", "version", "missing WHEEL", "second distribution", "wrong root"):
            with self.subTest(change=change):
                files = wheel_files()
                if change == "name":
                    files[INFO + "/METADATA"] = b"Name: other\nVersion: 0.1.0\n"
                elif change == "version":
                    files[INFO + "/METADATA"] = b"Name: cryptalis\nVersion: 999\n"
                elif change == "missing WHEEL":
                    del files[INFO + "/WHEEL"]
                elif change == "second distribution":
                    files["other-1.dist-info/METADATA"] = b"Name: other\nVersion: 1\n"
                else:
                    files = {name.replace(INFO, "other-1.dist-info"): value for name, value in files.items()}
                write_wheel(self.wheel, files, record_rows(files))
                with self.assertRaises(SystemExit):
                    inspect_wheel(self.wheel)

    def test_sdist_rejects_forbidden_paths_under_its_root(self):
        for name in ("tests/probe.py", "docs/probe.md", "examples/probe.py", "spikes/probe.py"):
            with self.subTest(name=name):
                write_sdist(self.sdist, [tarfile.TarInfo("cryptalis-0.1.0/" + name)])
                with self.assertRaises(SystemExit):
                    inspect_sdist(self.sdist)

    def test_sdist_rejects_links_special_files_duplicates_and_multiple_roots(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo("cryptalis-0.1.0/src/link")
                member.type, member.linkname = kind, "/etc/passwd"
                write_sdist(self.sdist, [member])
                with self.assertRaises(SystemExit):
                    inspect_sdist(self.sdist)
        for name in ("cryptalis-0.1.0/LICENSE", "other/LICENSE", "top-level-file"):
            with self.subTest(name=name):
                write_sdist(self.sdist, [tarfile.TarInfo(name)])
                with self.assertRaises(SystemExit):
                    inspect_sdist(self.sdist)


class InstalledArtifactTests(unittest.TestCase):
    def test_clean_install_is_bound_to_the_current_wheel(self):
        with tempfile.TemporaryDirectory(prefix="cryptalis-install-test-") as temporary:
            base = Path(temporary)
            environment = dict(os.environ, UV_OFFLINE="true", UV_CACHE_DIR=str(base / "cache"))
            built = subprocess.run(["uv", "build", "--offline", "--out-dir", str(base / "built")],
                                   cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next((base / "built").glob("*.whl"))
            target = base / "venv"
            venv.EnvBuilder(with_pip=False).create(target)
            python = target / "bin/python"
            located = subprocess.run([str(python), "-I", "-c",
                                      'import sysconfig; print(sysconfig.get_path("purelib"))'],
                                     check=True, capture_output=True, text=True)
            site = Path(located.stdout.strip())
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(site)

            def check():
                return subprocess.run([sys.executable, str(ROOT / "scripts/release_check.py"),
                                       "--output", str(base / "result"), "--python", str(python)],
                                      cwd=base, env=environment, capture_output=True, text=True)

            control = check()
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertEqual(json.loads(control.stdout)["clean_install"]["cli"], "passed")
            # Each mutation leaves an importable package and working CLI. Only the
            # comparison with the exact built wheel can expose the changed files.
            for name in ("cryptalis/__init__.py", INFO + "/METADATA", INFO + "/licenses/LICENSE"):
                with self.subTest(changed=name):
                    path = site / name
                    original = path.read_bytes()
                    try:
                        path.write_bytes(original + b"\n# stale installed artifact\n")
                        result = check()
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                    finally:
                        path.write_bytes(original)
            with self.subTest(changed="private interpreter failure output"):
                startup = site / "diagnostic.pth"
                startup.write_text("import sys; sys.stderr.write('PRIVATE_STARTUP_MARKER\\n')\n")
                module = site / MODULE
                original = module.read_bytes()
                try:
                    module.write_bytes(original + b"\n# different artifact\n")
                    result = check()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse("PRIVATE_STARTUP_MARKER" in result.stdout + result.stderr,
                                     "raw interpreter startup diagnostics escaped")
                finally:
                    startup.unlink()
                    module.write_bytes(original)
            with self.subTest(changed="unrecorded package module"):
                extra = site / "cryptalis/stale_module.py"
                extra.write_text("# left by an older distribution\n")
                try:
                    result = check()
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    extra.unlink()
            with self.subTest(changed="unchecked stale bytecode"):
                marker = base / "stale-bytecode-executed"
                stale_source = base / "stale.py"
                stale_source.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n")
                cached = Path(importlib.util.cache_from_source(str(site / MODULE)))
                cached.parent.mkdir(exist_ok=True)
                py_compile.compile(str(stale_source), cfile=str(cached), doraise=True,
                                   invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
                result = check()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(marker.exists(), "checker executed bytecode absent from the verified wheel")


if __name__ == "__main__":
    unittest.main()
