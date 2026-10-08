"""Field intent for the product compiler. This is not schema admission."""

import json
from dataclasses import dataclass
from uuid import UUID

from cryptalis.manifest.parser import ManifestInvalid, decode_manifest_json


@dataclass(frozen=True)
class ProtectedField:
    name: str
    field_id: UUID
    queries: tuple[str, ...]


@dataclass(frozen=True)
class ProtectedModel:
    model: str
    table_id: UUID
    tenant_column: str | None
    fields: tuple[ProtectedField, ...]


@dataclass(frozen=True)
class ProtectionDeclaration:
    domain_id: UUID
    models: tuple[ProtectedModel, ...]

    def canonical_bytes(self) -> bytes:
        """Return deterministic intent bytes, without a schema/lock claim."""
        document = {
            "schema": "cryptalis.protection/v1",
            "profile": "cf1",
            "domain_id": str(self.domain_id),
            "models": [
                {
                    "model": model.model,
                    "table_id": str(model.table_id),
                    "tenancy": (
                        {"single_tenant": True}
                        if model.tenant_column is None
                        else {"column": model.tenant_column}
                    ),
                    "fields": [
                        {
                            "name": field.name,
                            "field_id": str(field.field_id),
                            "protect": True,
                            "queries": list(field.queries),
                            "accept_leakage": list(field.queries),
                        }
                        for field in model.fields
                    ],
                }
                for model in self.models
            ],
        }
        return json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


def _object(value: object, members: set[str]) -> dict:
    if not isinstance(value, dict) or value.keys() != members:
        raise ManifestInvalid("Declaration object requires exactly the documented members")
    return value


def _name(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ManifestInvalid("Mapping names must be nonempty strings without NUL")
    return value


def _identity(value: object, used: set[UUID]) -> UUID:
    if not isinstance(value, str):
        raise ManifestInvalid("Stable IDs must be nonzero lowercase canonical UUIDs")
    try:
        identity = UUID(value)
    except ValueError:
        raise ManifestInvalid("Stable IDs must be nonzero lowercase canonical UUIDs") from None
    if str(identity) != value or identity.int == 0:
        raise ManifestInvalid("Stable IDs must be nonzero lowercase canonical UUIDs")
    if identity in used:
        raise ManifestInvalid("Stable IDs must be distinct within the declaration")
    used.add(identity)
    return identity


def _items(value: object) -> list:
    if not isinstance(value, list) or not value:
        raise ManifestInvalid("Models and fields must be nonempty arrays")
    return value


def _capabilities(value: object) -> set[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or item not in ("equality", "unique")
        for item in value
    ):
        raise ManifestInvalid("Queries and leakage acceptance permit only equality and unique")
    if len(value) != len(set(value)):
        raise ManifestInvalid("Capability lists must not contain duplicates")
    return set(value)


def parse_protection_declaration(raw: bytes) -> ProtectionDeclaration:
    """Validate bounded intent. Resolve names only in the later registry check.

    A valid declaration does not approve a mapping, schema, writer or migration.
    """
    document = _object(
        decode_manifest_json(raw), {"schema", "profile", "domain_id", "models"}
    )
    if document["schema"] != "cryptalis.protection/v1":
        raise ManifestInvalid("Use declaration schema cryptalis.protection/v1")
    if document["profile"] != "cf1":
        raise ManifestInvalid("Use profile cf1. Other profiles require admission")
    used: set[UUID] = set()
    domain_id = _identity(document["domain_id"], used)
    models = []
    model_names: set[str] = set()
    for item in _items(document["models"]):
        model = _object(item, {"model", "table_id", "tenancy", "fields"})
        name = _name(model["model"])
        if name in model_names:
            raise ManifestInvalid("Each model must occur once")
        model_names.add(name)
        table_id = _identity(model["table_id"], used)
        tenancy = model["tenancy"]
        if isinstance(tenancy, dict) and tenancy.keys() == {"column"}:
            tenant_column = _name(tenancy["column"])
        elif (
            isinstance(tenancy, dict)
            and tenancy.keys() == {"single_tenant"}
            and tenancy["single_tenant"] is True
        ):
            tenant_column = None
        else:
            raise ManifestInvalid("Declare one tenant column or single_tenant true")
        fields = []
        field_names: set[str] = set()
        for field_item in _items(model["fields"]):
            field = _object(
                field_item,
                {"name", "field_id", "protect", "queries", "accept_leakage"},
            )
            field_name = _name(field["name"])
            if field_name in field_names:
                raise ManifestInvalid("Each protected field must occur once per model")
            if field_name == tenant_column:
                raise ManifestInvalid("The tenant context column must remain unprotected")
            field_names.add(field_name)
            field_id = _identity(field["field_id"], used)
            if field["protect"] is not True:
                raise ManifestInvalid("Use protect true. Removal requires a verified transition")
            queries = _capabilities(field["queries"])
            if "unique" in queries:
                queries.add("equality")
            if _capabilities(field["accept_leakage"]) != queries:
                raise ManifestInvalid("Accept exactly the declared search leakage. Unique requires equality")
            fields.append(ProtectedField(field_name, field_id, tuple(sorted(queries))))
        models.append(
            ProtectedModel(name, table_id, tenant_column, tuple(sorted(fields, key=lambda f: f.name)))
        )
    return ProtectionDeclaration(domain_id, tuple(sorted(models, key=lambda m: m.model)))
