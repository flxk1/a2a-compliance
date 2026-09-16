"""Cheap drift guard: StageReceipt's wire schema `required` list must equal
lifecycle.StageReceipt's non-default dataclass fields. A field added to the
dataclass without a default, or a default removed, must fail this test until
the schema is updated to match -- catching schema/dataclass drift early."""

import dataclasses

from a2a_compliance.lifecycle import StageReceipt
from a2a_compliance.wire.schema_registry import load_schema


def _non_default_field_names(dc) -> set:
    return {
        f.name for f in dataclasses.fields(dc)
        if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
    }


def test_stage_receipt_schema_required_matches_dataclass_non_default_fields():
    schema = load_schema("StageReceipt")
    schema_required = set(schema["required"])
    dataclass_required = _non_default_field_names(StageReceipt)
    assert schema_required == dataclass_required
    assert dataclass_required == {"role", "capability", "status", "action_digest", "input_digest"}


def test_stage_receipt_defaulted_fields_are_not_in_schema_required():
    schema = load_schema("StageReceipt")
    dataclass_fields = {f.name for f in dataclasses.fields(StageReceipt)}
    defaulted = dataclass_fields - _non_default_field_names(StageReceipt)
    assert defaulted == {"output_digest", "reason"}
    assert not defaulted & set(schema["required"])
