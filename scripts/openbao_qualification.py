"""Run real OpenBao qualification against an already authorized PostgreSQL target.

Creates private, isolated, digest-pinned Docker services on loopback. Retains
their keys/storage, stops the services on exit, and never provisions or substitutes
PostgreSQL. Never archive the private work directory as public evidence.
"""
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from uuid import uuid4

import hvac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f'


class QualificationFailure(Exception):
    pass


def docker(*arguments):
    environment = dict(os.environ)
    for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        environment.pop(name, None)
    result = subprocess.run(['docker', '--host=unix:///var/run/docker.sock', *arguments],
                            env=environment, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise QualificationFailure('DockerCommandFailed')
    return result.stdout.strip()


def write_private(path, content):
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(content)


def certificates(workdir):
    """Generate a short-lived private test CA and a localhost TLS certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Cryptalis isolated test CA')])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    write_private(workdir / 'ca.pem', ca.public_bytes(serialization.Encoding.PEM))
    write_private(workdir / 'server.pem', leaf.public_bytes(serialization.Encoding.PEM))
    write_private(workdir / 'server.key', key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def wait_available(client):
    deadline = time.monotonic() + 30
    while True:
        try:
            return client.sys.is_initialized()
        except Exception:
            if time.monotonic() >= deadline:
                raise QualificationFailure('ServiceUnavailable') from None
            time.sleep(0.1)


def wait_active(client):
    """Unseal is not writable-leader readiness; poll only native read endpoints."""
    deadline = time.monotonic() + 30
    while True:
        try:
            health = client.sys.read_health_status(method='GET')
            leader = client.sys.read_leader_status()
            if (isinstance(health, dict) and health.get('initialized') is True
                    and health.get('sealed') is False and health.get('standby') is False
                    and leader.get('is_self') is True):
                return
        except Exception:
            pass
        if time.monotonic() >= deadline:
            raise QualificationFailure('ActiveServiceUnavailable') from None
        time.sleep(0.1)


def service_files(workdir):
    certificates(workdir)
    (workdir / 'data').mkdir(mode=0o700)
    write_private(workdir / 'server.hcl', b'''
storage "raft" {
  path = "/bao/work/data"
  node_id = "cryptalis-local-qualification"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/bao/work/server.pem"
  tls_key_file = "/bao/work/server.key"
}
api_addr = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
audit "file" "cryptalis-audit" {
  description = "Private local qualification audit; never publish raw records"
  options {
    file_path = "/bao/work/audit.jsonl"
    mode = "0600"
    format = "json"
    log_raw = "false"
    hmac_accessor = "true"
  }
}
''')


def start_container(workdir, container):
    # Pin the loopback port across restart. A binding race fails Docker startup.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    docker('run', '-d', '--name', container, '--user', f'{os.geteuid()}:{os.getegid()}',
           '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
           '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '-p', f'127.0.0.1:{port}:8200',
           '--mount', f'type=bind,src={workdir},dst=/bao/work', IMAGE,
           'server', '-config=/bao/work/server.hcl')
    return f'https://127.0.0.1:{port}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, required=True,
                        help='New private directory for service keys, storage and receipts; retained on exit.')
    parser.add_argument('--installed-wheel', type=Path)
    args = parser.parse_args()
    workdir = args.workdir.absolute()
    # A failed preflight stops before creating a service. No target is substituted.
    options = [] if args.installed_wheel is None else ['--installed-wheel', str(args.installed_wheel.resolve())]
    probe = subprocess.run([sys.executable, str(ROOT / 'scripts/test_postgres.py'),
                            *options, '--source-role', '--preflight-only'], cwd=ROOT)
    if probe.returncode:
        return probe.returncode
    workdir.mkdir(mode=0o700, parents=False, exist_ok=False)
    container = 'cryptalis-bao-' + uuid4().hex
    created, failure, cleanup = False, None, 'NOT_STARTED'
    try:
        service_files(workdir)
        endpoint = start_container(workdir, container)
        created = True
        write_private(workdir / 'container-name', container.encode())
        client = hvac.Client(url=endpoint, verify=str(workdir / 'ca.pem'),
                             allow_redirects=False, timeout=30)
        try:
            if wait_available(client):
                raise QualificationFailure('UnexpectedInitializedService')
            initialized = client.sys.initialize(secret_shares=1, secret_threshold=1)
            write_private(workdir / 'initialization.json', json.dumps(initialized).encode())
            client.sys.submit_unseal_key(initialized['keys'][0])
            wait_active(client)
        finally:
            client.session.close()
        config = dict(endpoint=endpoint, ca_cert=str(workdir / 'ca.pem'),
                      admin_token_file=str(workdir / 'initialization.json'),
                      isolated_container=container,
                      audit_file=str(workdir / 'audit.jsonl'), audit_device='cryptalis-audit')
        config_path = workdir / 'test-config.json'
        write_private(config_path, json.dumps(config).encode())
        environment = dict(os.environ, CRYPTALIS_OPENBAO_TEST_CONFIG=str(config_path))
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/test_postgres.py'),
            *options, '--source-role', '--receipt', str(workdir / 'tests.json'),
            '--scope', 'OpenBao 2.7.2 isolated TLS/Raft, native private audit, outage/restart, independent snapshot recovery and PostgreSQL lifecycle',
            '--', 'tests/test_openbao_protocol.py', 'tests/test_openbao_approle.py', 'tests/test_openbao_integration.py',
            'tests/test_doctor_provider.py',
            '-q', '--tb=short'], cwd=ROOT, env=environment)
        if result.returncode:
            raise QualificationFailure('TestsFailed')
        receipt = json.loads((workdir / 'tests.json').read_text())
        counts = receipt['pytest_report_counts']
        if (receipt['exit_code'] or any('skipped' in counts.get(phase, {})
                for phase in ('test_calls', 'setup', 'collection'))):
            raise QualificationFailure('IncompleteEvidence')
    except Exception as error:
        failure = error
    finally:
        if created:
            try:
                docker('stop', '--time', '15', container)
                cleanup = 'PASS'
            except Exception:
                cleanup = 'FAIL'
                if failure is None:
                    failure = QualificationFailure('CleanupFailed')
    report = dict(format='cryptalis.openbao-qualification/v1', image=IMAGE,
                  status='FAIL' if failure else 'PASS',
                  cleanup=cleanup,
                  failure=str(failure) if isinstance(failure, QualificationFailure)
                  else type(failure).__name__ if failure else None,
                  storage='single-node Raft with independent snapshot target; private keys and files retained',
                  tls='private test CA; certificate and hostname verification enabled',
                  audit='declarative private JSON file; native HMAC and reopen controls; raw records retained privately',
                  gate='UNKNOWN')
    write_private(workdir / 'qualification.json', json.dumps(report, indent=2).encode())
    print(json.dumps(report, sort_keys=True))
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
