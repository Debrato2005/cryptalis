"""Public attachment diagnoses unsafe logging before any connection or key access.

These deterministic admission controls use real SQLAlchemy engines and a
do_connect sentinel. No database or credentials are accessed. They can also run
directly with unittest; PostgreSQL qualification remains a separate run.
"""

import asyncio
import json
import unittest

from sqlalchemy import Column, MetaData, Table, Text, Uuid, create_engine, event
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import registry

import cryptalis.sqlalchemy as adapter


class AttachmentEnginePreflightTests(unittest.TestCase):
    def exercise(self, asynchronous, options, *, invalid_lock=False):
        secret = "SYNTHETIC_URL_SECRET_DO_NOT_REPORT"
        make_engine = create_async_engine if asynchronous else create_engine
        engine = make_engine(
            f"postgresql+psycopg://synthetic:{secret}@invalid.example/example",
            **options,
        )
        native = engine.sync_engine if asynchronous else engine
        mapping = registry(metadata=MetaData())
        table = Table(
            "customer", mapping.metadata,
            Column("id", Uuid, primary_key=True), Column("note", Text),
        )

        class Customer:
            pass

        mapper = mapping.map_imperatively(Customer, table)
        before = (native.echo, native.hide_parameters, native.url,
                  mapper.configured, table.schema, table.c.note.type)
        attempts = []

        def connect_sentinel(*args, **kwargs):
            attempts.append("connect")
            raise RuntimeError(secret)

        def key_sentinel(*args, **kwargs):
            attempts.append("keys")
            raise RuntimeError(secret)

        event.listen(native, "do_connect", connect_sentinel)
        lock = (b"invalid" if invalid_lock else
                json.dumps({"schema": "cryptalis.lock/v1", "profile": "cf1"}).encode())

        async def asynchronous_attach():
            return await adapter.attach(mapping, engine, lock=lock, keys=key_sentinel)

        try:
            with self.assertRaises(adapter.PolicyMismatch) as caught:
                if asynchronous:
                    asyncio.run(asynchronous_attach())
                else:
                    adapter.attach(mapping, engine, lock=lock, keys=key_sentinel)
            failure = caught.exception
            self.assertEqual(
                before,
                (native.echo, native.hide_parameters, native.url,
                 mapper.configured, table.schema, table.c.note.type),
            )
            self.assertNotIn(secret, str(failure))
            self.assertNotIn(secret, repr(failure.__dict__))
            self.assertFalse(failure.retryable)
            self.assertEqual(failure.effects, "none")
            return failure, attempts
        finally:
            if asynchronous:
                asyncio.run(engine.dispose())
            else:
                engine.dispose()
            mapping.dispose()

    def assert_unsafe_settings(self, asynchronous):
        for options in (
            {},
            {"echo": False},
            {"echo": False, "hide_parameters": False},
            {"echo": True, "hide_parameters": True},
            {"echo": "debug", "hide_parameters": True},
            {"echo": True, "hide_parameters": False},
        ):
            with self.subTest(options=options):
                failure, attempts = self.exercise(asynchronous, options)
                self.assertEqual(attempts, [], "Unsafe settings reached connection/key access.")
                self.assertEqual(failure.code, "UnsafeEngineLogging")
                self.assertEqual(failure.stage, "engine logging admission")
                self.assertIn("echo=False", failure.remedy)
                self.assertIn("hide_parameters=True", failure.remedy)

    def test_sync_unsafe_settings_fail_before_connection_or_keys(self):
        self.assert_unsafe_settings(False)

    def test_async_unsafe_settings_fail_before_connection_or_keys(self):
        self.assert_unsafe_settings(True)

    def test_accepted_settings_continue_to_existing_admission(self):
        for asynchronous in (False, True):
            for echo in (False, None):
                with self.subTest(asynchronous=asynchronous, echo=echo):
                    failure, attempts = self.exercise(
                        asynchronous, {"echo": echo, "hide_parameters": True},
                    )
                    self.assertEqual(attempts, ["connect"])
                    self.assertIs(type(failure), adapter.PolicyMismatch)

    def test_malformed_lock_keeps_existing_policy_failure(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                failure, attempts = self.exercise(asynchronous, {}, invalid_lock=True)
                self.assertEqual(attempts, [])
                self.assertIs(type(failure), adapter.PolicyMismatch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
