"""E1 conformance suite: DSSE/Ed25519 signature verification, trust-role
bindings, revocation and receipt-chain linkage. Loads tests/vectors/e1/*.

All signatures in tests/vectors/e1/ are produced by the TEST-ONLY dev signer
(`wire.dev_sign_subject`) over an ephemeral keypair generated once by
`tests/vectors/e1/keys.json` (private key hex committed there -- it is a
throwaway dev key, never a production key; see wire/signing.py). Trust
bindings are deployment config and are never read from the vectors
themselves -- `_trust_store()` below builds the injected TrustStore exactly
as a host would, independently of what each vector's payload claims.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from a2a_compliance.wire import (
    InMemoryRevocationStore,
    InMemoryTrustStore,
    verify,
    verify_chain,
)

VECTORS = Path(__file__).parent / "vectors" / "e1"
KEYS = json.loads((VECTORS / "keys.json").read_text(encoding="utf-8"))


def _load(*parts) -> dict:
    return json.loads((VECTORS / Path(*parts)).read_text(encoding="utf-8"))


def _pub(key_id: str) -> bytes:
    return bytes.fromhex(KEYS[key_id]["public_hex"])


def _trust_store() -> InMemoryTrustStore:
    """The deployment-config trust store used by every test below: key_id ->
    (public key, authorized object types, authorized StageReceipt roles).
    Deliberately narrow bindings, matching the 'fixed trust boundary' -- a
    key authorized for one role/type is not authorized for another."""
    store = InMemoryTrustStore()
    store.add("key-signer-1", _pub("key-signer-1"),
              frozenset({"StageReceipt"}), frozenset({"evidence-grounder"}))
    store.add("key-signer-wrong-role", _pub("key-signer-wrong-role"),
              frozenset({"StageReceipt"}), frozenset({"policy-author"}))
    store.add("key-signer-wrong-type", _pub("key-signer-wrong-type"),
              frozenset({"ExecutionPermit"}), frozenset())
    # key-signer-other is deliberately NOT added: it must resolve to
    # nothing, and its wrong_key.json signature (checked against
    # key-signer-1's registered public key) must fail regardless.
    return store


# --- positive -------------------------------------------------------------

def test_positive_vector_verifies():
    obj = _load("stage_receipt", "valid.json")
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok, result.errors
    assert result.errors == ()


def test_without_a_trust_store_signature_stays_opaque_e0_behavior():
    # Backward compatibility: an E1-signed object still verifies under
    # plain E0 rules when no trust_store is supplied -- the signature is
    # never inspected.
    obj = _load("stage_receipt", "valid.json")
    result = verify(obj, "StageReceipt")
    assert result.ok, result.errors


# --- negative: each of these must be REJECTED ------------------------------

def test_mutated_payload_is_rejected():
    # Signed correctly, then a field changed AND subject_digest re-stamped
    # to match -- the E0 digest check alone would pass this; only the
    # signature (over the ORIGINAL content) catches it.
    obj = _load("stage_receipt", "mutated_payload.json")
    assert obj["input_digest"] == "input-mutated-after-signing"
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("Ed25519 signature does not verify" in e for e in result.errors), result.errors


def test_wrong_key_signature_is_rejected():
    # Well-formed, digest matches, but signed by a DIFFERENT private key
    # than the one bound to key_id in the trust store.
    obj = _load("stage_receipt", "wrong_key.json")
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("Ed25519 signature does not verify" in e for e in result.errors), result.errors


def test_unknown_key_id_is_rejected():
    obj = _load("stage_receipt", "unknown_key_id.json")
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("unknown key_id" in e for e in result.errors), result.errors


def test_key_not_bound_to_role_is_rejected():
    # A cryptographically VALID signature from a key the trust store
    # authorizes only for role policy-author, not this receipt's
    # evidence-grounder role.
    obj = _load("stage_receipt", "key_not_bound_to_role.json")
    assert obj["role"] == "evidence-grounder"
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("key not bound to role" in e for e in result.errors), result.errors


def test_key_not_bound_to_object_type_is_rejected():
    # A cryptographically VALID signature from a key the trust store
    # authorizes only for ExecutionPermit, not StageReceipt.
    obj = _load("stage_receipt", "key_not_bound_to_type.json")
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("key not bound to object type" in e for e in result.errors), result.errors


def test_wrong_tool_owner_role_still_rejected_even_when_trust_engaged():
    # E0's TOOL_OWNERS capability<->role check is orthogonal to E1's
    # key<->role trust binding; composing a trust_store must not weaken it.
    obj = _load("..", "stage_receipt", "wrong_role.json")
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any(e.startswith("wrong-role:") for e in result.errors), result.errors


def test_stale_receipt_is_rejected_even_when_correctly_signed():
    obj = _load("stage_receipt", "stale.json")
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("stale" in e for e in result.errors), result.errors


def test_replayed_nonce_is_rejected_with_trust_store_engaged():
    from a2a_compliance.wire import InMemoryNonceStore

    first = _load("stage_receipt", "replay_first.json")
    second = _load("stage_receipt", "replay_second.json")
    assert first["run_id"] == second["run_id"]
    assert first["nonce"] == second["nonce"]

    nonce_store = InMemoryNonceStore()
    trust_store = _trust_store()
    r1 = verify(first, "StageReceipt", nonce_store=nonce_store, trust_store=trust_store)
    assert r1.ok, r1.errors
    r2 = verify(second, "StageReceipt", nonce_store=nonce_store, trust_store=trust_store)
    assert r2.ok is False
    assert any("nonce replay" in e for e in r2.errors), r2.errors


# --- negative: revocation ---------------------------------------------------

def test_revoked_key_is_rejected():
    obj = _load("revocation", "revoked_key.json")
    store = InMemoryRevocationStore()
    store.revoke("key", obj["key_id"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    result = verify(
        obj, "StageReceipt", trust_store=_trust_store(), revocation_store=store,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert result.ok is False
    assert any("revoked: key_id" in e for e in result.errors), result.errors


def test_revoked_run_is_rejected():
    obj = _load("revocation", "revoked_run.json")
    store = InMemoryRevocationStore()
    store.revoke("run", obj["run_id"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    result = verify(
        obj, "StageReceipt", trust_store=_trust_store(), revocation_store=store,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert result.ok is False
    assert any("revoked: run_id" in e for e in result.errors), result.errors


def test_revoked_permit_is_rejected():
    obj = _load("revocation", "revoked_permit.json")
    store = InMemoryRevocationStore()
    store.revoke("permit", obj["action_digest"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    result = verify(
        obj, "StageReceipt", trust_store=_trust_store(), revocation_store=store,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert result.ok is False
    assert any("revoked: permit" in e for e in result.errors), result.errors


def test_revocation_effective_in_the_future_does_not_yet_apply():
    obj = _load("revocation", "revoked_key.json")
    store = InMemoryRevocationStore()
    store.revoke("key", obj["key_id"], datetime(2099, 1, 1, tzinfo=timezone.utc))
    result = verify(
        obj, "StageReceipt", trust_store=_trust_store(), revocation_store=store,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert result.ok, result.errors


def test_without_a_revocation_store_a_revoked_object_is_not_flagged():
    # RevocationStore is an independent injected port, like NonceStore: no
    # store means no revocation check is performed.
    obj = _load("revocation", "revoked_key.json")
    result = verify(obj, "StageReceipt", trust_store=_trust_store())
    assert result.ok, result.errors


# --- negative: receipt-chain linkage ---------------------------------------

def _chain(*names):
    return [_load("chain", name) for name in names]


def test_valid_chain_verifies():
    receipts = _chain("000_valid.json", "001_valid.json", "002_valid.json")
    result = verify_chain(receipts, "StageReceipt", trust_store=_trust_store())
    assert result.ok, result.errors
    assert result.errors == ()


def test_chain_reordering_is_rejected():
    receipts = _chain("000_valid.json", "002_valid.json", "001_valid.json")
    result = verify_chain(receipts, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("broken link" in e for e in result.errors), result.errors


def test_chain_removal_is_rejected():
    # 001 removed: 002's prev_digest no longer matches its new predecessor.
    receipts = _chain("000_valid.json", "002_valid.json")
    result = verify_chain(receipts, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("broken link" in e for e in result.errors), result.errors


def test_chain_mutation_is_rejected():
    receipts = _chain("000_valid.json", "001_mutated.json", "002_valid.json")
    result = verify_chain(receipts, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    # the mutated link's own signature fails, AND it breaks the downstream link
    joined = "; ".join(result.errors)
    assert "chain[1]" in joined
    assert "chain[2]" in joined


def test_chain_missing_link_broken_genesis_is_rejected():
    # A genesis element that incorrectly claims a prev_digest.
    receipts = _chain("000_broken_genesis.json", "001_valid.json")
    result = verify_chain(receipts, "StageReceipt", trust_store=_trust_store())
    assert result.ok is False
    assert any("chain[0]" in e and "anchor" in e for e in result.errors), result.errors


def test_empty_chain_is_rejected():
    result = verify_chain([], "StageReceipt")
    assert result.ok is False
    assert result.errors == ("empty chain",)


def test_chain_composes_with_revocation():
    receipts = _chain("000_valid.json", "001_valid.json", "002_valid.json")
    store = InMemoryRevocationStore()
    store.revoke("key", receipts[0]["key_id"], datetime(2020, 1, 1, tzinfo=timezone.utc))
    result = verify_chain(
        receipts, "StageReceipt", trust_store=_trust_store(), revocation_store=store,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert result.ok is False
    assert any("revoked: key_id" in e for e in result.errors), result.errors


# --- bare-install proof: this whole module's imports must not need
# cryptography unless a trust_store is actually engaged -- see
# test_bare_install.py for the subprocess-level guarantee.

def test_signing_module_itself_needs_no_trust_store_to_import():
    import a2a_compliance.wire.signing as signing  # noqa: F401 -- import must succeed


@pytest.mark.parametrize("obj_type", ["StageReceipt"])
def test_prev_digest_is_optional_e0_objects_validate_unchanged(obj_type):
    from a2a_compliance.wire.schema_registry import validator_for

    obj = json.loads((Path(__file__).parent / "vectors" / "stage_receipt" / "valid.json").read_text())
    assert "prev_digest" not in obj
    validator = validator_for(obj_type)
    assert list(validator.iter_errors(obj)) == []
