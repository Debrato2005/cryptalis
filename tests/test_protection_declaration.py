"""Intent-parser evidence only. These tests do not replace PostgreSQL admission."""

import copy
import json
from uuid import UUID

import pytest

from cryptalis.manifest.declaration import parse_protection_declaration
from cryptalis.manifest.parser import ManifestInvalid


DOMAIN = "00000000-0000-4000-8000-000000000001"
TABLE = "00000000-0000-4000-8000-000000000002"
FIELD = "00000000-0000-4000-8000-000000000003"


def declaration():
    return {
        "schema": "cryptalis.protection/v1",
        "profile": "cf1",
        "domain_id": DOMAIN,
        "models": [{
            "model": "Customer",
            "table_id": TABLE,
            "tenancy": {"column": "tenant_id"},
            "fields": [{
                "name": "email",
                "field_id": FIELD,
                "protect": True,
                "queries": [],
                "accept_leakage": [],
            }],
        }],
    }


def parse(document):
    return parse_protection_declaration(json.dumps(document).encode())


def test_storage_only_and_explicit_tenancy_keep_typed_identity():
    document = declaration()
    intent = parse(document)
    assert intent.domain_id.bytes == bytes.fromhex("00000000000040008000000000000001")
    model, = intent.models
    field, = model.fields
    assert (model.model, model.tenant_column, field.name, field.queries) == (
        "Customer", "tenant_id", "email", (),
    )
    assert field.field_id == UUID(FIELD)
    document["models"][0]["tenancy"] = {"single_tenant": True}
    assert parse(document).models[0].tenant_column is None


def test_equivalent_declarations_have_identical_bytes_without_new_ids():
    document = declaration()
    fields = document["models"][0]["fields"]
    fields[0]["queries"] = ["unique"]
    fields[0]["accept_leakage"] = ["unique", "equality"]
    second = copy.deepcopy(fields[0])
    second.update(name="display_name", field_id="00000000-0000-4000-8000-000000000004")
    fields.append(second)
    before = parse(document).canonical_bytes()
    fields.reverse()
    for field in fields:
        field["queries"] = ["equality", "unique"]
        field["accept_leakage"].reverse()
    assert parse(document).canonical_bytes() == before
    assert parse_protection_declaration(before).canonical_bytes() == before
    assert parse(document).models[0].fields[0].queries == ("equality", "unique")


@pytest.mark.parametrize("queries,acceptance", [
    (["equality"], []), (["unique"], ["unique"]),
    ([], ["equality"]), (["equality"], ["equality", "unique"]),
    (["range"], ["range"]), (["in"], ["in"]),
    (["equality", "equality"], ["equality"]),
    (["equality"], ["equality", "equality"]),
    ([{}], []), (True, []), ([], {}),
])
def test_search_cannot_bypass_capability_or_leakage_admission(queries, acceptance):
    document = declaration()
    document["models"][0]["fields"][0].update(
        queries=queries, accept_leakage=acceptance,
    )
    with pytest.raises(ManifestInvalid):
        parse(document)


@pytest.mark.parametrize("tenancy", [
    {}, {"single_tenant": False}, {"single_tenant": 1},
    {"column": "tenant_id", "single_tenant": True},
    {"column": ""}, {"column": None}, {"column": "email"},
])
def test_tenant_scope_is_explicit_and_unprotected(tenancy):
    document = declaration()
    document["models"][0]["tenancy"] = tenancy
    with pytest.raises(ManifestInvalid):
        parse(document)


@pytest.mark.parametrize("attack", [
    "duplicate-model", "duplicate-field", "reused-id", "nil-id", "noncanonical-id",
    "unknown-member", "false-protect", "integer-protect", "empty-models", "empty-fields",
    "profile-downgrade", "wrong-schema", "missing-tenancy", "executable-normalizer",
])
def test_ambiguous_or_unadmitted_intent_fails_closed(attack):
    document = declaration()
    model = document["models"][0]
    field = model["fields"][0]
    if attack == "duplicate-model":
        document["models"].append(copy.deepcopy(model))
    elif attack == "duplicate-field":
        model["fields"].append(copy.deepcopy(field))
    elif attack == "reused-id":
        field["field_id"] = TABLE
    elif attack == "nil-id":
        field["field_id"] = str(UUID(int=0))
    elif attack == "noncanonical-id":
        field["field_id"] = "{" + FIELD + "}"
    elif attack == "unknown-member":
        document["key"] = "INJECTED_SECRET"
    elif attack == "false-protect":
        field["protect"] = False
    elif attack == "integer-protect":
        field["protect"] = 1
    elif attack == "empty-models":
        document["models"] = []
    elif attack == "empty-fields":
        model["fields"] = []
    elif attack == "profile-downgrade":
        document["profile"] = "plaintext"
    elif attack == "wrong-schema":
        document["schema"] = 1
    elif attack == "missing-tenancy":
        del model["tenancy"]
    elif attack == "executable-normalizer":
        field["normalizer"] = "module:callable"
    with pytest.raises(ManifestInvalid) as caught:
        parse(document)
    assert "INJECTED_SECRET" not in str(caught.value)


def test_duplicate_json_members_cannot_override_protection():
    raw = json.dumps(declaration()).replace('"protect": true', '"protect": false, "protect": true')
    with pytest.raises(ManifestInvalid, match="Duplicate"):
        parse_protection_declaration(raw.encode())


def test_model_names_are_data_and_do_not_import_code():
    document = declaration()
    document["models"][0]["model"] = "untrusted_package:execute"
    assert parse(document).models[0].model == "untrusted_package:execute"
