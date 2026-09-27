"""Ordering regression: the 'next-action' scope-RULE check in
`_verify_halt_approval` must run BEFORE `nonce_store.consume(...)`, so a
second, otherwise-fully-valid 'next-action' receipt for the same `run_id`
is rejected on the scope-rule ground -- and, crucially, WITHOUT burning its
own fresh nonce. If the consume ran first, the second receipt's nonce would
be spent even though the receipt was refused, silently discarding a
legitimate approval that could otherwise still be re-presented (e.g. after
switching to 'session' scope) or diagnosed by an operator inspecting nonce
state.
"""

from __future__ import annotations

from a2a_compliance import ComplianceAgent, Roster
from a2a_compliance import envelope as env
from a2a_compliance.authority import HUMAN_ROLE
from a2a_compliance.wire import canonical
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryTrustStore

FAR_FUTURE = "2999-01-01T00:00:00+00:00"
MAKER = "maker-1"
REASON = "off-mandate"
RUN_ID = "run-shared-1"


def _receipt(priv_key, key_id, *, nonce, digest, approver_id="human-1"):
    base = {
        "schema_version": "1.0.0",
        "type": "HumanApprovalReceipt",
        "issuer": f"issuer:{approver_id}",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": FAR_FUTURE,
        "run_id": RUN_ID,
        "nonce": nonce,
        "key_id": key_id,
        "approver": {"id": approver_id, "role": HUMAN_ROLE},
        "permitted_action_digest": digest,
        "scope": "next-action",
        "reservations": [],
    }
    base["subject_digest"] = canonical.subject_digest(base)
    base["signature"] = dev_sign_subject(base, priv_key)
    return base


def test_second_next_action_receipt_rejected_and_its_nonce_left_unspent(inbox):
    """First 'next-action' receipt authorises a halt; a second, otherwise
    valid 'next-action' receipt for the same run (fresh nonce, fresh digest)
    must be rejected with the scope-rule reason -- and its own nonce must
    remain unconsumed afterwards, proving the scope-rule check runs before
    the consume."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-approver", pub,
        frozenset({"HumanApprovalReceipt"}), frozenset({HUMAN_ROLE}),
        identity="human-1",
    )
    comp = ComplianceAgent(
        session_id="comp-1", role="policy-compliance", inbox=inbox,
        roster=Roster(), trust_store=trust_store,
    )

    first_digest = env.halt_digest("comp-1", MAKER, REASON)
    first_receipt = _receipt(priv, "key-approver", nonce="nonce-first", digest=first_digest)
    first = comp.halt(MAKER, reason_ref=REASON, approval=first_receipt)
    assert first.dispatched is True

    second_reason_ref = "off-mandate-again"
    second_digest = env.halt_digest("comp-1", MAKER, second_reason_ref)
    second_nonce = "nonce-second"
    second_receipt = _receipt(priv, "key-approver", nonce=second_nonce, digest=second_digest)
    second = comp.halt(MAKER, reason_ref=second_reason_ref, approval=second_receipt)

    assert second.dispatched is False
    assert "next-action" in second.denied_reason
    assert "already used" in second.denied_reason

    # The scope-rule rejection must not have consumed the second receipt's
    # own nonce -- it was refused before the single-use consume ran.
    assert comp.nonce_store.seen(RUN_ID, second_nonce) is False
