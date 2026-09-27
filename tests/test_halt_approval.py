"""Halt gated on a VERIFIED human approval receipt (OWASP quick win #2;
AI Act Art. 14(4) proof-of-human-presence posture).

In AUTHENTICATED mode (a TrustStore configured on the `ComplianceAgent`),
`halt()` must never dispatch on `confirm=True` alone: it requires a
`HumanApprovalReceipt` that VERIFIES (reusing
`wire.verification.verify_human_approval`, E1, read-only) and is bound to
this exact halt via `envelope.halt_digest(...)`, approved by a human
identity distinct from the sender. BARE mode (no trust store) keeps the
original advisory `confirm=True` gate -- documented in `channel.py` as
advisory-only.

FIX 2(b) (key-bound approver + single-use + scope): WHO approved is decided
by the SIGNING KEY's bound role/identity (deployment config via the trust
store), never by the receipt's own self-declared `approver.id`/
`approver.role` fields -- every `key-*` fixture below is registered with an
explicit `identity=` and, where it must count as a human approval, the
`human` role. A receipt is also now SINGLE-USE (its `(run_id, nonce)` is
consumed from a `NonceStore`) and its `scope` must be a recognized value;
see `tests/test_channel_identity_replay.py` for the reuse/scope/self-signed
regressions turned directly from the recorded exploit scripts.
"""

from __future__ import annotations

import pytest

from a2a_compliance import ComplianceAgent, Roster
from a2a_compliance import envelope as env
from a2a_compliance.authority import HUMAN_ROLE
from a2a_compliance.wire import canonical
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryTrustStore

FAR_FUTURE = "2999-01-01T00:00:00+00:00"
MAKER = "maker-1"
REASON = "off-mandate"


@pytest.fixture
def keys():
    return {
        "approver": generate_dev_keypair(),
        "other_key": generate_dev_keypair(),
        "as_sender": generate_dev_keypair(),
        "as_maker": generate_dev_keypair(),
        "nonhuman": generate_dev_keypair(),
    }


@pytest.fixture
def trust_store(keys):
    store = InMemoryTrustStore()
    # The good case: a key genuinely bound to the human role, vouching for a
    # distinct human identity.
    store.add(
        "key-approver", keys["approver"][1],
        frozenset({"HumanApprovalReceipt"}), frozenset({HUMAN_ROLE}),
        identity="human-1",
    )
    # A human-role key whose bound identity happens to equal the SENDER
    # (comp-1) -- must still be rejected as self-approval, regardless of
    # what the receipt's own `approver` field claims.
    store.add(
        "key-as-sender", keys["as_sender"][1],
        frozenset({"HumanApprovalReceipt"}), frozenset({HUMAN_ROLE}),
        identity="comp-1",
    )
    # A human-role key whose bound identity happens to equal the MAKER
    # being halted -- must still be rejected (approver cannot be the maker).
    store.add(
        "key-as-maker", keys["as_maker"][1],
        frozenset({"HumanApprovalReceipt"}), frozenset({HUMAN_ROLE}),
        identity=MAKER,
    )
    # A key bound to an identity but NOT to the human role -- the receipt
    # may still self-declare `approver.role: "human"`, but the KEY's bound
    # role is what counts.
    store.add(
        "key-nonhuman", keys["nonhuman"][1],
        frozenset({"HumanApprovalReceipt"}), frozenset(),
        identity="human-2",
    )
    return store


@pytest.fixture
def comp(inbox, trust_store):
    """An AUTHENTICATED-mode compliance agent: a TrustStore is configured."""
    return ComplianceAgent(
        session_id="comp-1", role="policy-compliance", inbox=inbox,
        roster=Roster(), trust_store=trust_store,
    )


@pytest.fixture
def bare_comp(inbox):
    """A BARE-mode compliance agent: no TrustStore configured."""
    return ComplianceAgent(
        session_id="comp-1", role="policy-compliance", inbox=inbox, roster=Roster(),
    )


def _receipt(
    priv_key, key_id, *,
    maker=MAKER, reason_ref=REASON, approver_id="human-1",
    approver_role=HUMAN_ROLE, digest=None, run_id="run-1", nonce="nonce-1",
    scope="session",
):
    digest = digest if digest is not None else env.halt_digest("comp-1", maker, reason_ref)
    base = {
        "schema_version": "1.0.0",
        "type": "HumanApprovalReceipt",
        "issuer": f"issuer:{approver_id}",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": FAR_FUTURE,
        "run_id": run_id,
        "nonce": nonce,
        "key_id": key_id,
        "approver": {"id": approver_id, "role": approver_role},
        "permitted_action_digest": digest,
        "scope": scope,
        "reservations": [],
    }
    base["subject_digest"] = canonical.subject_digest(base)
    base["signature"] = dev_sign_subject(base, priv_key)
    return base


# --- the five literal acceptance cases (authenticated mode) ----------------

def test_no_receipt_not_dispatched(comp):
    res = comp.halt(MAKER, reason_ref=REASON)
    assert res.dispatched is False
    assert res.surfaced_to_human is True


def test_receipt_bound_to_different_digest_not_dispatched(comp, keys):
    wrong_digest = env.halt_digest("comp-1", "some-other-maker", REASON)
    receipt = _receipt(keys["approver"][0], "key-approver", digest=wrong_digest)
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is False
    assert "digest" in res.denied_reason


def test_receipt_approver_is_sender_not_dispatched(comp, keys):
    # key-as-sender is genuinely bound to the human role and to identity
    # "comp-1" -- a fully valid human approval, except that identity IS the
    # sender's own session_id, so it must still be rejected (self-approval).
    receipt = _receipt(keys["as_sender"][0], "key-as-sender", approver_id="comp-1")
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is False


def test_valid_receipt_by_distinct_authorized_human_dispatched(comp, keys):
    receipt = _receipt(keys["approver"][0], "key-approver")
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is True
    assert res.message is not None
    assert res.message.verb.value == "halt"


def test_confirm_true_with_no_receipt_not_dispatched(comp):
    res = comp.halt(MAKER, reason_ref=REASON, confirm=True)
    assert res.dispatched is False


# --- additional coverage -----------------------------------------------

def test_receipt_approver_is_the_maker_not_dispatched(comp, keys):
    # key-as-maker is genuinely bound to the human role and to identity
    # MAKER -- a fully valid human approval by key-bound-identity standards,
    # except the approver IS the maker being halted, so it must be rejected.
    receipt = _receipt(keys["as_maker"][0], "key-as-maker", approver_id=MAKER)
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is False


def test_receipt_approver_role_not_human_not_dispatched(comp, keys):
    # The receipt self-declares approver.role="human", but the SIGNING KEY
    # is not bound to the human role -- the key-bound role is what counts,
    # never the receipt's own self-declared field.
    receipt = _receipt(
        keys["nonhuman"][0], "key-nonhuman", approver_id="human-2", approver_role="human",
    )
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is False
    assert "human" in res.denied_reason


def test_receipt_forged_key_not_dispatched(comp, keys):
    # Signed with a key never registered in the trust store.
    receipt = _receipt(keys["other_key"][0], "key-unregistered")
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is False


def test_receipt_tampered_after_signing_not_dispatched(comp, keys):
    receipt = _receipt(keys["approver"][0], "key-approver")
    tampered = dict(receipt)
    tampered["scope"] = "next-action"  # mutate a signed field post-signature
    res = comp.halt(MAKER, reason_ref=REASON, approval=tampered)
    assert res.dispatched is False


def test_receipt_expired_not_dispatched(comp, keys):
    receipt = _receipt(keys["approver"][0], "key-approver")
    receipt["expires_at"] = "2000-01-01T00:00:00+00:00"
    receipt["subject_digest"] = canonical.subject_digest(receipt)
    receipt["signature"] = dev_sign_subject(receipt, keys["approver"][0])
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is False


def test_bare_mode_confirm_true_still_dispatches(bare_comp):
    """BARE mode (no trust store) keeps the original advisory gate: this is
    NOT a regression, it is the documented bare-mode floor -- see
    `channel.py::halt`'s docstring."""
    res = bare_comp.halt(MAKER, reason_ref=REASON, confirm=True)
    assert res.dispatched is True


def test_bare_mode_without_confirm_not_dispatched(bare_comp):
    res = bare_comp.halt(MAKER, reason_ref=REASON)
    assert res.dispatched is False


# --- FIX 2(b): single-use + scope ------------------------------------------

def test_valid_receipt_is_single_use(comp, keys):
    """A valid, distinct-human-approved receipt dispatches once; the exact
    same receipt object presented a second time is denied -- its
    `(run_id, nonce)` was consumed by the first, successful use."""
    receipt = _receipt(keys["approver"][0], "key-approver")
    first = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert first.dispatched is True

    second = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert second.dispatched is False


def test_receipt_unknown_scope_not_dispatched(comp, keys):
    receipt = _receipt(keys["approver"][0], "key-approver", scope="whenever-i-feel-like-it")
    receipt["subject_digest"] = canonical.subject_digest(receipt)
    receipt["signature"] = dev_sign_subject(receipt, keys["approver"][0])
    res = comp.halt(MAKER, reason_ref=REASON, approval=receipt)
    assert res.dispatched is False
