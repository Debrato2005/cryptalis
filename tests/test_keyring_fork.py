"""Fork-inherited keyring mutexes must not block process-bound refusal."""

import asyncio
import multiprocessing
import os

import pytest

from cryptalis.crypto import KeyUnavailable, open_text, seal_text
from test_cf1 import RECORD, TENANT, descriptor, setup_keys


def _child_prepare(sender, ring):
    phase = b"inherited preparation"
    try:
        for prepare in (ring.prepare, lambda: asyncio.run(ring.prepare_async())):
            try:
                prepare()
            except KeyUnavailable:
                continue
            raise AssertionError("Inherited preparation did not refuse")
        phase = b"fresh child preparation"
        _, fresh_ring = setup_keys()
        fresh = fresh_ring.prepare()
        field = descriptor()
        frame = seal_text("fresh child", field, TENANT, RECORD, fresh)
        assert open_text(frame, field, TENANT, RECORD, fresh) == "fresh child"
        sender.send_bytes(b"sync and async refused; fresh child works")
    except BaseException:
        sender.send_bytes(b"failed: " + phase)
    finally:
        sender.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Requires the POSIX fork boundary")
def test_inherited_locked_keyring_refuses_before_mutex_and_parent_remains_usable():
    _, ring = setup_keys()
    prepared, field = ring.prepare(), descriptor()
    frame = seal_text("parent preserved", field, TENANT, RECORD, prepared)
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    child = context.Process(target=_child_prepare, args=(sender, ring))
    try:
        with ring._lock:
            child.start()
            sender.close()
            child.join(timeout=5)
            assert not child.is_alive(), "Inherited preparation blocked on the keyring mutex"
            assert child.exitcode == 0, "Child process did not exit cleanly"
            assert receiver.poll(0), "Child process returned no safe outcome"
            assert receiver.recv_bytes(128) == b"sync and async refused; fresh child works"
    finally:
        sender.close()
        receiver.close()
        if child.pid is not None:
            if child.is_alive():
                child.kill()
            child.join(timeout=5)
            assert not child.is_alive(), "Child cleanup did not finish"
        child.close()
    assert open_text(frame, field, TENANT, RECORD, prepared) == "parent preserved"
    assert open_text(frame, field, TENANT, RECORD, ring.prepare()) == "parent preserved"
