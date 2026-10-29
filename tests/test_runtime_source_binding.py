"""The PostgreSQL wrapper binds loaded Cryptalis code to its selected artifact."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

import pytest

from test_postgres import ROOT


WRAPPER = ROOT / "scripts" / "test_postgres.py"


def _run_binding(*arguments, pythonpath, extra_environment=None):
    environment = dict(os.environ)
    paths = pythonpath if isinstance(pythonpath, (tuple, list)) else (pythonpath,)
    environment["PYTHONPATH"] = os.pathsep.join(map(str, paths))
    if extra_environment is not None:
        environment.update(extra_environment)
    result = subprocess.run(
        [sys.executable, str(WRAPPER), "--runtime-binding-only", *map(str, arguments)],
        cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
    return result


def _write_wheel_fixture(wheel, installed_root):
    source_root = ROOT / "src" / "cryptalis"
    installed_package = installed_root / "cryptalis"
    installed_package.mkdir(parents=True)
    with zipfile.ZipFile(wheel, "w") as archive:
        for source in sorted(source_root.rglob("*.py")):
            name = "cryptalis/" + source.relative_to(source_root).as_posix()
            content = source.read_bytes()
            archive.writestr(name, content)
            destination = installed_root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)


def test_source_mode_rejects_a_different_checkout_before_database_access():
    with tempfile.TemporaryDirectory(prefix="cryptalis-wrong-source-") as temporary:
        foreign = Path(temporary) / "site"
        package = foreign / "cryptalis"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("# different checkout\n")

        result = _run_binding(pythonpath=foreign)

    assert result.returncode == 4
    assert "Verification.RuntimeBindingFailed" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr
    assert "different checkout" not in result.stdout + result.stderr


def test_foreign_import_is_rejected_without_executing_or_printing_it():
    with tempfile.TemporaryDirectory(prefix="cryptalis-noisy-import-") as temporary:
        foreign = Path(temporary) / "site"
        package = foreign / "cryptalis"
        package.mkdir(parents=True)
        marker = Path(temporary) / "executed"
        (package / "__init__.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nprint('foreign-noise')\n")

        result = _run_binding(pythonpath=foreign)

        assert result.returncode == 4
        assert "foreign-noise" not in result.stdout + result.stderr
        assert not marker.exists()


def test_source_mode_reports_the_isolated_checkout():
    result = _run_binding(pythonpath=ROOT / "src")

    assert result.returncode == 0
    report = json.loads(result.stdout)
    binding = report["runtime_binding"]
    assert binding["mode"] == "source"
    assert binding["runtime_root"] == str((ROOT / "src" / "cryptalis").resolve())
    assert binding["module_count"] > 1
    assert len(binding["modules_sha256"]) == 64


def test_installed_wheel_mode_checks_all_module_bytes_and_wheel_digest():
    with tempfile.TemporaryDirectory(prefix="cryptalis-wheel-binding-") as temporary:
        root = Path(temporary)
        site = root / "site"
        site.mkdir()
        wheel = root / "cryptalis-fixture.whl"
        _write_wheel_fixture(wheel, site)

        result = _run_binding("--installed-wheel", wheel, pythonpath=site)
        assert result.returncode == 0
        binding = json.loads(result.stdout)["runtime_binding"]
        assert binding["mode"] == "installed-wheel"
        assert binding["runtime_root"] == str((site / "cryptalis").resolve())
        assert binding["wheel_sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
        assert binding["module_count"] > 1

        installed_module = site / "cryptalis" / "migration.py"
        installed_module.write_bytes(installed_module.read_bytes() + b"\n# tampered\n")
        tampered = _run_binding("--installed-wheel", wheel, pythonpath=site)

    assert tampered.returncode == 4
    assert "Verification.RuntimeBindingFailed" in tampered.stdout
    assert "Traceback" not in tampered.stdout + tampered.stderr


@pytest.mark.parametrize("module_file", [None, "foreign.pyc"])
def test_rejects_loaded_module_without_admitted_python_source(module_file):
    with tempfile.TemporaryDirectory(prefix="cryptalis-loaded-module-") as temporary:
        startup = Path(temporary)
        startup.joinpath("sitecustomize.py").write_text(
            "import sys, types\n"
            "module = types.ModuleType('cryptalis.injected')\n"
            f"module.__file__ = {module_file!r}\n"
            "sys.modules['cryptalis.injected'] = module\n")

        result = _run_binding(pythonpath=(startup, ROOT / "src"))

    assert result.returncode == 4
    assert "Verification.RuntimeBindingFailed" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_diagnostic_modes_are_mutually_exclusive_and_do_not_start_probes():
    result = subprocess.run(
        [sys.executable, str(WRAPPER), "--development-preflight",
         "--runtime-binding-only"],
        cwd=ROOT, env=dict(os.environ), capture_output=True, text=True, check=False)

    assert result.returncode == 2
    assert "not allowed with argument" in result.stderr
    assert "Verification.RuntimeBindingFailed" not in result.stdout + result.stderr
