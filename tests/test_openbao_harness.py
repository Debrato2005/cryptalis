"""Fault controls for disposable container retirement; native recovery tests prove success."""
import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def retirement(tmp_path, monkeypatch):
    pytest.importorskip('hvac')
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    module = importlib.import_module('openbao_qualification')
    name, identity = 'cryptalis-bao-' + 'a' * 32, 'b' * 64
    details = dict(Name='/' + name, Id=identity, Config=dict(Image=module.IMAGE),
        HostConfig=dict(ReadonlyRootfs=True),
        Mounts=[dict(Type='bind', Source=str(tmp_path), Destination='/bao/work', RW=True)])
    private = tmp_path / 'retained.key'
    private.write_bytes(b'PRIVATE_RETAINED_CUSTODY')
    calls, fault = [], [None]
    def docker(*args, output=None):
        calls.append(args)
        if args == ('inspect', name): return json.dumps([details])
        if args[0] == 'inspect': return 'running' if fault[0] == 'running' else 'exited'
        if args[0] == fault[0]: raise module.QualificationFailure('DockerCommandFailed')
        if args[0] == 'logs': output.write(b'PRIVATE_NATIVE_CONTAINER_LOG\n')
        return ''
    monkeypatch.setattr(module, 'docker', docker)
    return module, tmp_path, name, details, calls, fault


@pytest.mark.parametrize('change', ['writable_root', 'wrong_mount', 'wrong_image'])
def test_retirement_refuses_unowned_container_before_stop(retirement, change):
    module, root, name, details, calls, _ = retirement
    if change == 'writable_root': details['HostConfig']['ReadonlyRootfs'] = False
    elif change == 'wrong_mount': details['Mounts'][0]['Source'] = str(root / 'other')
    else: details['Config']['Image'] = 'untrusted-image'
    with pytest.raises(module.QualificationFailure, match='ContainerIdentityMismatch'):
        module.retire_container(root, name)
    assert [call[0] for call in calls] == ['inspect']
    assert (root / 'retained.key').read_bytes() == b'PRIVATE_RETAINED_CUSTODY'
    assert not (root / 'container.log').exists()


@pytest.mark.parametrize('stage', ['stop', 'running', 'logs', 'fsync', 'directory_sync', 'rm'])
def test_retirement_preserves_custody_and_surfaces_partial_cleanup(retirement, monkeypatch, stage):
    module, root, name, _, calls, fault = retirement
    fault[0] = stage
    if stage in ('fsync', 'directory_sync'):
        sync_calls = []
        def unavailable(_):
            sync_calls.append(True)
            if stage == 'fsync' or len(sync_calls) == 2:
                raise OSError('PublicInjectedSyncFailure')
        monkeypatch.setattr(module.os, 'fsync', unavailable)
    with pytest.raises((module.QualificationFailure, OSError)) as caught:
        module.retire_container(root, name)
    assert 'PRIVATE' not in str(caught.value)
    assert (root / 'retained.key').read_bytes() == b'PRIVATE_RETAINED_CUSTODY'
    assert any(call[0] == 'rm' for call in calls) == (stage == 'rm')
    if (root / 'container.log').exists():
        assert (root / 'container.log').stat().st_mode & 0o777 == 0o600
    if stage in ('fsync', 'directory_sync', 'rm'):
        assert (root / 'container.log').read_bytes() == b'PRIVATE_NATIVE_CONTAINER_LOG\n'
