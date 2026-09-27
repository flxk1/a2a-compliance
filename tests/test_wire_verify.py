"""E0 conformance suite: loads tests/vectors/* and asserts fail-closed
verification. Convention: valid.json passes; every other *.json in a type's
directory must be REJECTED (never silently pass)."""

import copy
import json
from pathlib import Path

import pytest

from datetime import datetime, timezone

from a2a_compliance.wire import InMemoryNonceStore, WIRE_TYPES, verify
from a2a_compliance.wire.canonical import subject_digest
from a2a_compliance.wire.schema_registry import WIRE_TYPES as REG_TYPES
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryTrustStore

VECTORS = Path(__file__).parent / "vectors"
NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)
FAR_FUTURE = "2099-01-01T00:00:00+00:00"

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


def test_stage_receipt_satisfied_rejects_null_output_digest():
    # regression: schema must mirror the dataclass's `not self.output_digest`
    # test (null is falsy), not just field presence.
    obj = _load(VECTORS / "stage_receipt" / "satisfied_output_digest_null.json")
    assert obj["output_digest"] is None
    result = verify(obj, "StageReceipt")
    assert result.ok is False
    assert any("schema:" in e for e in result.errors), result.errors


def test_stage_receipt_satisfied_rejects_empty_output_digest():
    # regression: "" is present and non-null but still falsy -- the dataclass
    # rejects it; a presence-only schema check would not.
    obj = _load(VECTORS / "stage_receipt" / "satisfied_output_digest_empty.json")
    assert obj["output_digest"] == ""
    result = verify(obj, "StageReceipt")
    assert result.ok is False
    assert any("schema:" in e for e in result.errors), result.errors


def test_stage_receipt_not_applicable_rejects_whitespace_only_reason():
    # regression: schema must mirror the dataclass's `reason.strip()` test,
    # not bare minLength (which whitespace-only strings satisfy).
    obj = _load(VECTORS / "stage_receipt" / "not_applicable_reason_whitespace.json")
    assert obj["reason"].strip() == ""
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


# --- FIX 1: plain verify() itself rejects a HumanApprovalReceipt whose
# signing key is not bound to a human role, or whose bound identity differs
# from the self-declared approver -- WITHOUT the opt-in verify_human_approval
# helper. See wire/verification.py's `_human_approval_wire_findings`.

def _signed_human_approval_receipt(priv, *, key_id, approver_id, run_id="run-fix1", nonce="nonce-fix1") -> dict:
    obj = {
        "schema_version": "1.0.0", "type": "HumanApprovalReceipt",
        "issuer": f"issuer:{approver_id}",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": FAR_FUTURE,
        "run_id": run_id, "nonce": nonce, "key_id": key_id,
        "approver": {"id": approver_id, "role": "human"},
        "permitted_action_digest": "a" * 64,
        "scope": "next-action", "reservations": [],
    }
    obj["subject_digest"] = subject_digest(obj)
    obj["signature"] = dev_sign_subject(obj, priv)
    return obj


def test_plain_verify_rejects_key_not_bound_to_human_role():
    """(i) The signing key is authorized to issue HumanApprovalReceipt and
    self-declares a human approver, but its trust binding carries no
    'human' role. Plain verify() -- no opt-in helper -- must reject this on
    its own."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-not-human", pub, frozenset({"HumanApprovalReceipt"}), frozenset({"agent"}),
        identity="someone",
    )
    obj = _signed_human_approval_receipt(priv, key_id="key-not-human", approver_id="someone")

    result = verify(obj, "HumanApprovalReceipt", trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("human role" in e for e in result.errors), result.errors


def test_plain_verify_rejects_approver_id_not_equal_to_bound_identity():
    """(ii) The signing key IS bound to the human role, but its bound
    identity differs from the receipt's self-declared approver.id. Plain
    verify() -- no opt-in helper -- must reject this on its own."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-human-imposter", pub, frozenset({"HumanApprovalReceipt"}), frozenset({"human"}),
        identity="human-genuine",
    )
    obj = _signed_human_approval_receipt(priv, key_id="key-human-imposter", approver_id="human-imposter")

    result = verify(obj, "HumanApprovalReceipt", trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("does not match the signing key's bound" in e for e in result.errors), result.errors


def test_plain_verify_accepts_a_genuinely_human_bound_receipt():
    """Positive control for the two rejections above: a key genuinely bound
    to the human role AND to the exact approver identity passes plain
    verify() with no opt-in helper needed."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-human-genuine", pub, frozenset({"HumanApprovalReceipt"}), frozenset({"human"}),
        identity="human-genuine",
    )
    obj = _signed_human_approval_receipt(priv, key_id="key-human-genuine", approver_id="human-genuine")

    result = verify(obj, "HumanApprovalReceipt", trust_store=trust_store, now=NOW)
    assert result.ok, result.errors


def test_digests_fixture_matches_valid_vectors():
    index = _load(VECTORS / "digests.json")
    for dir_name, type_name in DIR_TO_TYPE.items():
        obj = _load(VECTORS / dir_name / "valid.json")
        assert index[dir_name]["type"] == type_name
        assert index[dir_name]["subject_digest"] == obj["subject_digest"]
