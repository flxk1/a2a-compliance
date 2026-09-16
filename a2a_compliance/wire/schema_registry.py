"""Load the packaged Draft 2020-12 wire schemas and build a resolving validator
per type. Local-only resolution: schema `$id`s are `urn:` identifiers, never
fetched over a network (jsonschema's `referencing.Registry` is populated
in-process from the packaged files)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

_BASE_ID = "urn:a2a-compliance:wire:envelope-base"

WIRE_TYPES: dict[str, str] = {
    "ControlRequest": "control-request.schema.json",
    "ContextManifest": "context-manifest.schema.json",
    "StageReceipt": "stage-receipt.schema.json",
    "HumanApprovalReceipt": "human-approval-receipt.schema.json",
    "ExecutionPermit": "execution-permit.schema.json",
    "ToolReceipt": "tool-receipt.schema.json",
    "Reconciliation": "reconciliation.schema.json",
    "Revocation": "revocation.schema.json",
}


def _schemas_dir():
    return files("a2a_compliance.wire.schemas")


@lru_cache(maxsize=None)
def load_schema(type_name: str) -> dict:
    if type_name not in WIRE_TYPES:
        raise KeyError(f"unknown wire type: {type_name!r}")
    path = _schemas_dir().joinpath(WIRE_TYPES[type_name])
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def _envelope_base_schema() -> dict:
    path = _schemas_dir().joinpath("envelope-base.schema.json")
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def _registry() -> Registry:
    registry = Registry().with_resource(
        _BASE_ID, Resource.from_contents(_envelope_base_schema()),
    )
    for type_name in WIRE_TYPES:
        schema = load_schema(type_name)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


@lru_cache(maxsize=None)
def validator_for(type_name: str) -> Draft202012Validator:
    schema = load_schema(type_name)
    return Draft202012Validator(
        schema, registry=_registry(), format_checker=FormatChecker(),
    )
