"""Compose existing CI checks; stage named public evidence, never cluster files.

Both modes use disposable local PostgreSQL 16. Release also creates an isolated
OpenBao service whose keys and private files never enter public evidence.
This helper does not publish artifacts or qualify a production release gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from fresh_cluster_qualification import start_cluster, stop_cluster, provision, write_home
from release_check import inspect_install


ROOT = Path(__file__).resolve().parents[1]


class CheckFailed(Exception):
    def __init__(self, code):
        self.code = code


class Qualification:
    def __init__(self, mode, workdir, evidence):
        self.mode, self.workdir, self.evidence = mode, workdir, evidence
        self.status = {'format': 'cryptalis.ci/v1', 'mode': mode, 'outcome': 'RUNNING',
                       'steps': [], 'production_gates': 'UNKNOWN'}

    def save(self):
        temporary = self.evidence / 'status.tmp'
        temporary.write_text(json.dumps(self.status, indent=2) + '\n')
        temporary.replace(self.evidence / 'status.json')

    def run(self, name, command, *, environment=None, output=None):
        step = {'name': name, 'outcome': 'RUNNING'}
        self.status['steps'].append(step)
        self.save()
        print('CI step:', name, flush=True)
        started = time.monotonic()
        if output is None:
            result = subprocess.run(command, cwd=ROOT, env=environment)
        else:
            with output.open('xb') as stream:
                result = subprocess.run(command, cwd=ROOT, env=environment, stdout=stream)
        step.update(exit_code=result.returncode, elapsed_seconds=time.monotonic() - started,
                    outcome='PASS' if result.returncode == 0 else 'FAIL')
        self.save()
        if result.returncode != 0:
            raise CheckFailed(result.returncode)

    def stage(self, source, name):
        if source.is_symlink():
            raise ValueError('Evidence must not be a symlink')
        if source.is_file():
            shutil.copyfile(source, self.evidence / name)

    def source(self):
        self.run('artifact-integrity regressions', [sys.executable, 'scripts/test_release_check.py'])
        self.run('offline rewrap protocol regressions', [sys.executable, 'scripts/test_rewrap_protocol.py'])
        self.run('complete default source suite', [sys.executable, 'scripts/online_qualification.py',
            '--workdir', str(self.workdir / 'source'), '--', 'tests', '-q'])
        receipt = json.loads((self.workdir / 'source/receipt.json').read_text())
        if receipt['exit_code'] != 0 or receipt['counts'].get('passed', 0) == 0:
            raise CheckFailed(1)
        # Skipped optional/external cells remain visible in the wrapper receipt.
        self.status['pytest_counts'] = receipt['counts']

    def release(self):
        artifacts = self.workdir / 'artifacts'
        self.run('reproducible wheel sdist SBOM inspection', [sys.executable,
            'scripts/release_check.py', '--output', str(artifacts),
            '--extra', 'openbao', '--extra', 'sqlmodel', '--extra', 'gcp',
            '--receipt', str(self.workdir / 'release.json')])
        wheels = list(artifacts.glob('cryptalis-*.whl'))
        if len(wheels) != 1:
            raise CheckFailed(1)
        wheel = wheels[0]
        dependencies = self.workdir / 'dependencies.txt'
        self.run('export locked hashed wheel-test dependencies', ['uv', 'export', '--locked',
            '--all-extras', '--no-emit-project', '--format', 'requirements-txt',
            '--output-file', str(dependencies)])
        installed = self.workdir / 'installed'
        self.run('create isolated wheel interpreter', ['uv', 'venv', '--python', sys.executable, str(installed)])
        python = installed / 'bin/python'
        self.run('install hashed dependencies', ['uv', 'pip', 'sync', '--python', str(python),
            '--require-hashes', '--only-binary', ':all:', str(dependencies)])
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        requirement = self.workdir / 'wheel.txt'
        requirement.write_text(f'cryptalis @ {wheel.as_uri()} --hash=sha256:{digest}\n')
        self.run('install exact inspected wheel', ['uv', 'pip', 'install', '--python', str(python),
            '--no-deps', '--require-hashes', '--only-binary', ':all:', '-r', str(requirement)])
        self.run('installed dependency consistency', ['uv', 'pip', 'check', '--python', str(python)])
        step = {'name': 'installed file and CLI inspection', 'outcome': 'RUNNING'}
        self.status['steps'].append(step)
        self.save()
        try:
            inspection = inspect_install(python, wheel, self.workdir)
        except BaseException:
            step['outcome'] = 'FAIL'
            raise
        step['outcome'] = 'PASS'
        self.save()
        (self.workdir / 'install.json').write_text(json.dumps(inspection, indent=2) + '\n')
        # Keep the native scanner toolchain
        # outside the application and provider interpreter and dependency lock.
        scanner_dependencies = self.workdir / 'scanner-dependencies.txt'
        self.run('export isolated locked scanner dependencies', ['uv', 'export', '--project', 'tools/scanner',
            '--locked', '--no-emit-project', '--no-dev', '--format', 'requirements-txt',
            '--output-file', str(scanner_dependencies)])
        scanner_environment = self.workdir / 'scanner'
        self.run('create isolated scanner interpreter', ['uv', 'venv', '--python', sys.executable,
            str(scanner_environment)])
        self.run('install hashed scanner dependencies', ['uv', 'pip', 'sync', '--python',
            str(scanner_environment / 'bin/python'), '--require-hashes', '--only-binary', ':all:',
            str(scanner_dependencies)])
        self.run('export scanner SBOM', ['uv', 'export', '--project', 'tools/scanner', '--locked',
            '--no-emit-project', '--no-dev', '--format', 'cyclonedx1.5',
            '--output-file', str(self.workdir / 'scanner-sbom.cdx.json')])
        self.run('audit frozen scanner toolchain', ['uv', 'audit', '--project', 'tools/scanner', '--frozen',
            '--output-format', 'json'], output=self.workdir / 'scanner-audit.json')
        (self.workdir / 'scanner-toolchain.json').write_text(json.dumps(dict(
            format='cryptalis.scanner-toolchain/v1', version='0.51.0', isolated=True,
            lock_sha256=hashlib.sha256((ROOT / 'tools/scanner/uv.lock').read_bytes()).hexdigest(),
            requirements_sha256=hashlib.sha256(scanner_dependencies.read_bytes()).hexdigest(),
            production_gate='UNKNOWN'), indent=2) + '\n')
        cluster = None
        try:
            primary = self.workdir / 'primary'
            primary.mkdir(mode=0o700)
            cluster, port, password = start_cluster(primary)
            manifest = {'owner_role': 'cryptalis_ci_owner', 'runtime_role': 'cryptalis_ci_runtime',
                        'database': 'cryptalis_ci'}
            credentials = provision(port, password, manifest, manifest['database'] + '_native')
            home = write_home(primary, port, manifest, credentials, source_database=manifest['database'])
            environment = dict(os.environ, CRYPTALIS_TEST_CONFIG_DIR=str(home), PYTHONPATH='')
            scanner_scope = dict(environment, CRYPTALIS_TEST_SCANNER=str(scanner_environment / 'bin/ast-grep'))
            self.run('installed Doctor native code inventory', [str(python), 'scripts/test_postgres.py',
                '--installed-wheel', str(wheel), '--source-role',
                '--scope', 'Installed Doctor with isolated native ast-grep, privacy and process/omission controls',
                '--receipt', str(self.workdir / 'installed-code-receipt.json'), '--',
                'tests/test_doctor_code.py', 'tests/test_doctor_code_native.py', '-q'], environment=scanner_scope)
            receipt = json.loads((self.workdir / 'installed-code-receipt.json').read_text())
            if (receipt['exit_code'] != 0 or set(receipt['counts']) != {'passed'}
                    or receipt['pytest_report_counts']['collection']
                    or receipt['runtime_binding']['mode'] != 'installed-wheel'
                    or receipt['runtime_binding']['wheel_sha256'] != digest):
                raise CheckFailed(1)
            self.run('installed ORM and shared initialization/Doctor context', [str(python),
                'scripts/test_postgres.py', '--installed-wheel', str(wheel), '--source-role',
                '--scope', 'Installed ORM DML, fork isolation and shared key-free init/Doctor context with native failure controls',
                '--receipt', str(self.workdir / 'installed-sqlmodel-receipt.json'), '--',
                'tests/test_sqlmodel_bridge.py', 'tests/test_sqlmodel_async.py', 'tests/test_sqlalchemy_fork.py',
                'tests/test_single_tenant_update.py', 'tests/test_single_tenant_delete.py',
                'tests/test_initialization_cli.py', 'tests/test_application_config.py',
                'tests/test_application_rotation.py', 'tests/test_application_online.py',
                'tests/test_application_modification.py', 'tests/test_modification_boundaries.py',
                'tests/test_modification_contexts.py', 'tests/test_modification_recovery.py',
                'tests/test_modification_queries.py', 'tests/test_modification_storage.py',
                'tests/test_modification_status_cli.py', 'tests/test_rotation_status_cli.py',
                'tests/test_point_returning_labels.py',
                'tests/test_point_update_rows.py',
                'tests/test_insert_returning_labels.py', 'tests/test_bulk_returning_boundary.py',
                'tests/test_bulk_returning_rows.py::test_multiple_protected_returning_outputs_authenticate_each_frame',
                'tests/test_point_update_returning.py', 'tests/test_point_update_returning_more.py',
                'tests/test_point_update_returning_boundary.py', 'tests/test_point_delete_returning.py',
                'tests/test_point_delete_returning_more.py', 'tests/test_point_delete_returning_boundary.py',
                'tests/test_uuid_point_boundary.py', '-q'],
                environment=environment)
            receipt = json.loads((self.workdir / 'installed-sqlmodel-receipt.json').read_text())
            if (receipt['exit_code'] != 0 or receipt['counts'].get('passed', 0) == 0
                    or set(receipt['counts']) != {'passed'}
                    or receipt['pytest_report_counts']['collection']
                    or receipt['runtime_binding']['mode'] != 'installed-wheel'
                    or receipt['runtime_binding']['wheel_sha256'] != digest):
                raise CheckFailed(1)
            self.run('installed Google SDK protocol and PostgreSQL lifecycle', [str(python),
                'scripts/test_postgres.py', '--installed-wheel', str(wheel), '--source-role',
                '--scope', 'Google SDK local protocol transport and real PostgreSQL; no live cloud custody',
                '--receipt', str(self.workdir / 'installed-google-kms-receipt.json'), '--',
                'tests/test_google_kms.py', '-q'], environment=environment)
            receipt = json.loads((self.workdir / 'installed-google-kms-receipt.json').read_text())
            if (receipt['exit_code'] != 0 or receipt['counts'].get('passed', 0) == 0
                    or set(receipt['counts']) != {'passed'} or receipt['pytest_report_counts']['collection']
                    or receipt['runtime_binding']['mode'] != 'installed-wheel'
                    or receipt['runtime_binding']['wheel_sha256'] != digest):
                raise CheckFailed(1)
            self.run('installed OpenBao TLS outage and PostgreSQL lifecycle', [str(python),
                'scripts/openbao_qualification.py', '--workdir', str(self.workdir / 'openbao'),
                '--installed-wheel', str(wheel)], environment=environment)
            self.run('installed shared configuration on genuine fresh recovery', [str(python),
                'scripts/fresh_cluster_qualification.py', '--workdir', str(self.workdir / 'application-fresh'),
                '--application-config', '--installed-wheel', str(wheel)], environment=environment)
            for phase in ('export', 'restore'):
                receipt = json.loads((self.workdir / f'application-fresh/{phase}-receipt.json').read_text())
                if (receipt['exit_code'] != 0 or receipt['counts'] != {'passed': 1 if phase == 'export' else 2}
                        or receipt['pytest_report_counts']['collection']
                        or receipt['runtime_binding']['mode'] != 'installed-wheel'
                        or receipt['runtime_binding']['wheel_sha256'] != digest):
                    raise CheckFailed(1)
            self.run('installed keyword public-slot genuine fresh recovery', [str(python),
                'scripts/fresh_cluster_qualification.py', '--workdir', str(self.workdir / 'fresh'),
                '--integer', '32', '--column-name', 'integer', '--public-slots',
                '--installed-wheel', str(wheel)], environment=environment)
            for phase in ('export', 'restore'):
                receipt = json.loads((self.workdir / f'fresh/{phase}-receipt.json').read_text())
                if (receipt['exit_code'] != 0 or receipt['counts'] != {'passed': 1}
                        or receipt['pytest_report_counts']['collection']
                        or receipt['runtime_binding']['mode'] != 'installed-wheel'
                        or receipt['runtime_binding']['wheel_sha256'] != digest):
                    raise CheckFailed(1)
            for profile, dirname in (('enable', 'modification-fresh'), ('disable', 'storage-modification-fresh')):
                self.run('installed modified-field ' + profile + ' genuine fresh recovery', [str(python),
                    'scripts/fresh_cluster_qualification.py', '--workdir', str(self.workdir / dirname),
                    '--modification', profile, '--installed-wheel', str(wheel)], environment=environment)
                for phase in ('export', 'restore'):
                    receipt = json.loads((self.workdir / f'{dirname}/{phase}-receipt.json').read_text())
                    if (receipt['exit_code'] != 0 or receipt['counts'] != {'passed': 1}
                            or receipt['pytest_report_counts']['collection']
                            or receipt['runtime_binding']['mode'] != 'installed-wheel'
                            or receipt['runtime_binding']['wheel_sha256'] != digest):
                        raise CheckFailed(1)
        finally:
            if cluster is not None:
                primary_failure = sys.exc_info()[0] is not None
                try:
                    stop_cluster(cluster)
                except Exception:
                    self.status['cleanup'] = 'FAIL: source cluster shutdown'
                    self.save()
                    if not primary_failure:
                        raise

    def collect(self):
        # No recursive globs: private homes, URLs, passwords, logs, SQL dumps
        # and cluster contents must never enter an upload directory.
        for relative, name in (
                ('source/receipt.json', 'source-receipt.json'),
                ('release.json', 'release-receipt.json'), ('install.json', 'install-receipt.json'),
                ('installed-sqlmodel-receipt.json', 'installed-sqlmodel-receipt.json'),
                ('installed-code-receipt.json', 'installed-code-receipt.json'),
                ('scanner-toolchain.json', 'scanner-toolchain.json'),
                ('scanner-sbom.cdx.json', 'scanner-sbom.cdx.json'),
                ('scanner-audit.json', 'scanner-audit.json'),
                ('installed-google-kms-receipt.json', 'installed-google-kms-receipt.json'),
                ('openbao/tests.json', 'installed-openbao-tests.json'),
                ('openbao/qualification.json', 'installed-openbao-qualification.json'),
                ('fresh/export-receipt.json', 'installed-export-receipt.json'),
                ('fresh/restore-receipt.json', 'installed-restore-receipt.json'),
                ('application-fresh/export-receipt.json', 'installed-application-export-receipt.json'),
                ('application-fresh/restore-receipt.json', 'installed-application-restore-receipt.json'),
                ('modification-fresh/export-receipt.json', 'installed-modification-export-receipt.json'),
                ('modification-fresh/restore-receipt.json', 'installed-modification-restore-receipt.json'),
                ('storage-modification-fresh/export-receipt.json', 'installed-storage-modification-export-receipt.json'),
                ('storage-modification-fresh/restore-receipt.json', 'installed-storage-modification-restore-receipt.json'),
                ('fresh/integer-32-journey-receipt.json', 'installed-journey-receipt.json')):
            self.stage(self.workdir / relative, name)
        # Only successfully inspected release artifacts are eligible for upload.
        release = self.workdir / 'release.json'
        if release.is_file() and not release.is_symlink():
            document = json.loads(release.read_text())
            for name in (*document['artifacts'], 'sbom.cdx.json', 'SHA256SUMS'):
                if Path(name).name != name:
                    raise ValueError('Invalid inspected artifact name')
                self.stage(self.workdir / 'artifacts' / name, name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('source', 'release'))
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    workdir, evidence = args.workdir.absolute(), args.evidence.absolute()
    if workdir == evidence or workdir in evidence.parents or evidence in workdir.parents:
        parser.error('private work and public evidence directories must be separate')
    workdir.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    check = Qualification(args.mode, workdir, evidence)
    check.save()
    code = 1
    try:
        getattr(check, args.mode)()
        check.status['outcome'] = 'PASS'
        code = 0
    except CheckFailed as error:
        code = error.code if 0 < error.code < 126 else 1
        check.status['outcome'] = 'FAIL'
    except BaseException as error:
        check.status.update(outcome='FAIL', error_type=type(error).__name__)
        print('CI helper failed:', type(error).__name__, flush=True)
    finally:
        try:
            check.collect()
        except Exception as error:
            check.status.update(outcome='FAIL', evidence_error=type(error).__name__)
            code = code or 1
        check.save()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
