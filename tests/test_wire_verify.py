"""E0 conformance suite: loads tests/vectors/* and asserts fail-closed
verification. Convention: valid.json passes; every other *.json in a type's
directory must be REJECTED (never silently pass)."""

import copy
import json
from pathlib import Path

import pytest

from a2a_compliance.wire import InMemoryNonceStore, WIRE_TYPES, verify
from a2a_compliance.wire.schema_registry import WIRE_TYPES as REG_TYPES

VECTORS = Path(__file__).parent / "vectors"

DIR_TO_TYPE = {
    "control_request": "ControlRequest",
    "context_manifest": "ContextManifest",
    "stage_receipt": "StageReceipt",
    "human_approval_receipt": "HumanApprovalReceipt",
    "execution_permit": "ExecutionPermit",
    "tool_receipt": "ToolReceipt",
    "reconciliation": "Reconciliation",
    "revocation": "Revocation",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _type_dirs():
    return sorted(p for p in VECTORS.iterdir() if p.is_dir() and p.name in DIR_TO_TYPE)


@pytest.mark.parametrize("type_dir", _type_dirs(), ids=lambda p: p.name)
def test_valid_vector_passes(type_dir):
    obj = _load(type_dir / "valid.json")
    result = verify(obj, DIR_TO_TYPE[type_dir.name])
    assert result.ok, result.errors
    assert result.errors == ()


def _negative_vectors():
    cases = []
    for type_dir in _type_dirs():
        for path in sorted(type_dir.glob("*.json")):
            if path.name == "valid.json":
                continue
            cases.append(path)
    return cases


@pytest.mark.parametrize("path", _negative_vectors(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_negative_vector_is_rejected(path):
    type_name = DIR_TO_TYPE[path.parent.name]
    obj = _load(path)
    result = verify(obj, type_name)
    assert result.ok is False, f"{path} unexpectedly passed"
    assert result.errors, f"{path} rejected with no reason"


def test_digest_mismatch_vectors_report_digest_error():
    for type_dir in _type_dirs():
        obj = _load(type_dir / "digest_mismatch.json")
        result = verify(obj, DIR_TO_TYPE[type_dir.name])
        assert any("subject_digest mismatch" in e for e in result.errors), result.errors


def test_tampered_field_vectors_report_digest_error():
    for type_dir in _type_dirs():
        obj = _load(type_dir / "tampered_field.json")
        result = verify(obj, DIR_TO_TYPE[type_dir.name])
        assert any("subject_digest mismatch" in e for e in result.errors), result.errors


def test_missing_required_field_vectors_report_schema_error():
    for type_dir in _type_dirs():
        obj = _load(type_dir / "missing_required_field.json")
        result = verify(obj, DIR_TO_TYPE[type_dir.name])
        assert any(e.startswith("schema:") for e in result.errors), result.errors


def test_stale_expiry_vectors_report_staleness_only():
    for type_dir in _type_dirs():
        obj = _load(type_dir / "stale_expiry.json")
        result = verify(obj, DIR_TO_TYPE[type_dir.name])
        assert result.errors == ("expires_at is in the past (stale)",), (type_dir.name, result.errors)


def test_stage_receipt_wrong_role_is_rejected():
    obj = _load(VECTORS / "stage_receipt" / "wrong_role.json")
    result = verify(obj, "StageReceipt")
    assert result.ok is False
    assert any(e.startswith("wrong-role:") for e in result.errors), result.errors


def test_stage_receipt_not_applicable_needs_a_reason():
    obj = _load(VECTORS / "stage_receipt" / "not_applicable_without_reason.json")
    result = verify(obj, "StageReceipt")
    assert result.ok is False
    assert any("schema:" in e for e in result.errors), result.errors


def test_stage_receipt_satisfied_needs_an_output_digest():
    obj = _load(VECTORS / "stage_receipt" / "satisfied_without_output_digest.json")
    result = verify(obj, "StageReceipt")
    assert result.ok is False
    assert any("schema:" in e for e in result.errors), result.errors


def test_replayed_nonce_is_rejected_on_second_use():
    first = _load(VECTORS / "replay" / "first.json")
    second = _load(VECTORS / "replay" / "second.json")
    assert first["run_id"] == second["run_id"]
    assert first["nonce"] == second["nonce"]

    store = InMemoryNonceStore()
    r1 = verify(first, "ControlRequest", nonce_store=store)
    assert r1.ok, r1.errors
    r2 = verify(second, "ControlRequest", nonce_store=store)
    assert r2.ok is False
    assert any("nonce replay" in e for e in r2.errors), r2.errors


def test_replayed_object_without_a_nonce_store_is_not_flagged_as_replay():
    # E0 defines the port; no store means no replay check is performed --
    # a host MUST inject a durable NonceStore to get this protection.
    first = _load(VECTORS / "replay" / "first.json")
    second = _load(VECTORS / "replay" / "second.json")
    assert verify(first, "ControlRequest").ok
    assert verify(second, "ControlRequest").ok


def test_unknown_type_is_rejected():
    obj = _load(VECTORS / "control_request" / "valid.json")
    result = verify(obj, "NotARealType")
    assert result.ok is False
    assert "unknown type" in result.errors[0]


def test_type_field_mismatch_is_rejected():
    obj = copy.deepcopy(_load(VECTORS / "control_request" / "valid.json"))
    obj["type"] = "ContextManifest"
    result = verify(obj, "ControlRequest")
    assert result.ok is False
    assert any("type mismatch" in e for e in result.errors), result.errors


def test_all_eight_wire_types_are_registered():
    assert WIRE_TYPES == REG_TYPES
    assert set(WIRE_TYPES) == set(DIR_TO_TYPE.values())


def test_digests_fixture_matches_valid_vectors():
    index = _load(VECTORS / "digests.json")
    for dir_name, type_name in DIR_TO_TYPE.items():
        obj = _load(VECTORS / dir_name / "valid.json")
        assert index[dir_name]["type"] == type_name
        assert index[dir_name]["subject_digest"] == obj["subject_digest"]
