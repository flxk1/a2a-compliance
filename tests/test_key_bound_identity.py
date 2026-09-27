"""G2 regression suite: key-bound identity at the wire layer (FIX 1) plus
the REFUSED-not-REVIEW_REQUIRED vocabulary for a forged/tampered/unbound
governance block (FIX 3). Every test here works at the VERIFICATION layer
(`wire.verification.verify_human_approval`, `wire.verification.verify`) or
the ADMISSION layer (`wire.admission.admit`) directly -- never through
`ComplianceAgent.halt`/the control channel, which are owned by another leg
and out of this file's territory.

The first test reproduces, at this layer, exactly the exploit recorded in
the scratchpad `exploit.py`: a sender's OWN agent key -- authorized for the
`HumanApprovalReceipt` object type but bound to no human role and no human
identity -- signs a `HumanApprovalReceipt` that merely SELF-DECLARES
`approver.id`/`approver.role`. Before this fix, `wire.verification.verify`
(the only check that existed) accepted it outright: nothing checked the
signing key's role or identity against the claimed approver. Run against
HEAD (27c9cff), every test in this module either fails outright or raises
ImportError (`verify_human_approval` does not exist yet) -- see the recorded
run below this module's tests, kept in the maker's report, not in this file
itself (a docstring is not evidence; the actual pytest output is).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from a2a_compliance import (
    ACTION_NO_STEER,
    CapabilityInventory,
    ComplianceTeam,
    ControlRequest,
    GovernanceBlock,
    GroundingContext,
    GroundingResult,
    TEAM_ROLES,
)
from a2a_compliance.governance_block import SignedGovernanceBlock, sign_governance_block
from a2a_compliance.team import TeamProfile
from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import AdmissionDecision, admit, dev_issuer
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryTrustStore
from a2a_compliance.wire.verification import verify, verify_human_approval

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
FAR_FUTURE = "2099-01-01T00:00:00+00:00"


def _stamp_and_sign(obj: dict, priv: bytes) -> dict:
    obj = dict(obj)
    obj["subject_digest"] = canonical.subject_digest(obj)
    obj["signature"] = dev_sign_subject(obj, priv)
    return obj


def _approval(*, key_id, approver_id, approver_role, nonce="nonce-approval-0001", **overrides) -> dict:
    base = {
        "schema_version": "1.0.0",
        "type": "HumanApprovalReceipt",
        "issuer": "issuer:comp-1",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": FAR_FUTURE,
        "run_id": "run-1",
        "nonce": nonce,
        "key_id": key_id,
        "approver": {"id": approver_id, "role": approver_role},
        "permitted_action_digest": "a" * 64,
        "scope": "next-action",
        "reservations": [],
    }
    base.update(overrides)
    return base


# --- 1. the recorded exploit, reproduced at the verification layer --------

def test_exploit_sender_agent_key_claiming_human_approver_is_rejected():
    """Exact shape of `exploit.py`: the SENDER's own agent key is bound for
    the `HumanApprovalReceipt` object type (so signature/type/schema are all
    genuinely valid) but for the agent's OWN role, never 'human', and no
    identity -- yet the receipt self-declares `approver.role: 'human'`,
    `approver.id: 'not-me-honest'`. Both the PLAIN `verify()` (baked in, not
    opt-in -- see `verification._human_approval_wire_findings`) and the
    richer `verify_human_approval` helper must reject this."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-comp-1-agent", pub,
        frozenset({"HumanApprovalReceipt", "A2AControlMessage"}),
        frozenset({"policy-compliance"}),  # bound role: agent, NOT human
        # deliberately no identity= -- this key never vouches for anyone
    )
    approval = _approval(key_id="key-comp-1-agent", approver_id="not-me-honest", approver_role="human")
    signed = _stamp_and_sign(approval, priv)

    plain = verify(signed, "HumanApprovalReceipt", trust_store=trust_store, now=NOW)
    assert plain.ok is False
    assert any("human role" in e for e in plain.errors)

    result = verify_human_approval(signed, trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("human role" in e for e in result.errors)


# --- 2. approver id != key's bound identity --------------------------------

def test_approver_id_not_equal_to_key_bound_identity_is_rejected():
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-human-1", pub, frozenset({"HumanApprovalReceipt"}), frozenset({"human"}),
        identity="human-1",
    )
    approval = _approval(key_id="key-human-1", approver_id="human-2", approver_role="human")
    signed = _stamp_and_sign(approval, priv)

    result = verify_human_approval(signed, trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("does not match the signing key's bound identity" in e for e in result.errors)


# --- 3. key lacking the human role -----------------------------------------

def test_key_not_bound_to_human_role_is_rejected():
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-not-human", pub, frozenset({"HumanApprovalReceipt"}), frozenset({"rung-2"}),
        identity="human-1",  # even WITH a matching identity, no 'human' role
    )
    approval = _approval(key_id="key-not-human", approver_id="human-1", approver_role="human")
    signed = _stamp_and_sign(approval, priv)

    result = verify_human_approval(signed, trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("human role" in e for e in result.errors)


def test_human_role_key_with_no_bound_identity_is_rejected():
    """Bound to the right role (human), but the key was never bound to ANY
    identity -- key-bound identity's own backward-compat rule says this
    fails closed, not 'skip the identity check'."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-human-no-identity", pub, frozenset({"HumanApprovalReceipt"}), frozenset({"human"}),
        # deliberately no identity=
    )
    approval = _approval(key_id="key-human-no-identity", approver_id="human-1", approver_role="human")
    signed = _stamp_and_sign(approval, priv)

    result = verify_human_approval(signed, trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("cannot vouch for who approved this" in e for e in result.errors)


def test_sender_identity_equal_to_approver_identity_is_rejected():
    """The additive `sender_identity=` guard: even a fully valid human
    approval must not be usable as its own approver."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-human-1", pub, frozenset({"HumanApprovalReceipt"}), frozenset({"human"}),
        identity="human-1",
    )
    approval = _approval(key_id="key-human-1", approver_id="human-1", approver_role="human")
    signed = _stamp_and_sign(approval, priv)

    ok_result = verify_human_approval(signed, trust_store=trust_store, now=NOW)
    assert ok_result.ok, ok_result.errors
    assert ok_result.approver_identity == "human-1"

    self_result = verify_human_approval(
        signed, trust_store=trust_store, now=NOW, sender_identity="human-1",
    )
    assert self_result.ok is False
    assert any("self-approval" in e for e in self_result.errors)


# --- governance-block plumbing for the admission-layer tests below --------

def _full_inventory():
    tools, skills, contracts, distributions = set(), set(), set(), set()
    for role in TEAM_ROLES:
        for cap in role.capabilities:
            {"tool": tools, "skill": skills, "contract": contracts,
             "distribution": distributions}[cap.kind.value].add(cap.name)
    return CapabilityInventory.from_iterables(
        tools=tools, skills=skills, contracts=contracts, distributions=distributions,
    )


def _plan(governance, *, target_kind="edit", maker_id="maker-1"):
    request = ControlRequest(
        GroundingContext(maker_id=maker_id, proposed_action={"bearer": maker_id, "action": target_kind}),
        target_kind, governance, profile=TeamProfile.PROTOCOL,
    )
    result = GroundingResult([], None, ACTION_NO_STEER, "test result")
    return ComplianceTeam(_full_inventory()).assess(request, result)


GOVERNANCE = GovernanceBlock.from_dict({"actions": [{"kind": "edit"}]})


# --- 4. governance block signed by a key whose bound identity IS the maker -

def test_governance_block_signed_by_key_bound_to_maker_identity_is_refused():
    """Key-bound identity closes a hole the OLD self-declared check missed:
    a signer can claim ANY `signer_identity` string in the object it signs.
    The maker-distinctness check must compare the KEY's bound identity
    (deployment config), not the self-declared field, against the maker."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-maker", pub, frozenset({"GovernanceBlock"}), frozenset({"policy-author"}),
        identity="maker-1",  # the KEY is bound to the maker's own identity
    )
    maker_issuer = dev_issuer("key-maker", "maker-1", priv)
    signed = sign_governance_block(
        GOVERNANCE, key_id=maker_issuer.key_id, identity=maker_issuer.identity, sign=maker_issuer.sign,
    )
    plan = _plan(GOVERNANCE, maker_id="maker-1")

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=trust_store,
        signed_governance_block=signed, policy_author_role="policy-author", now=NOW,
    )
    assert result.decision is AdmissionDecision.REFUSED
    assert any("signed by the maker" in r for r in result.reasons)


# --- 5. author field forged to an identity different from the key's -------

def test_governance_block_author_field_forged_is_refused():
    """The SELF-DECLARED `signer_identity` field ('the author says...') is
    forged to a DIFFERENT identity than the key is actually bound to -- a
    key registered as 'policy:real-author' signs, but the object claims
    'policy:someone-else' as its author. Must be refused, distinctly from
    (and before) the maker-distinctness check."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-author", pub, frozenset({"GovernanceBlock"}), frozenset({"policy-author"}),
        identity="policy:real-author",
    )
    # Sign with the identity string forged to a different value than the
    # key's bound identity -- `sign_governance_block` will happily embed
    # whatever `identity=` a caller passes; that is exactly the surface
    # this check closes.
    forging_issuer = dev_issuer("key-author", "policy:someone-else", priv)
    signed = sign_governance_block(
        GOVERNANCE, key_id=forging_issuer.key_id, identity=forging_issuer.identity, sign=forging_issuer.sign,
    )
    plan = _plan(GOVERNANCE, maker_id="maker-1")

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=trust_store,
        signed_governance_block=signed, policy_author_role="policy-author", now=NOW,
    )
    assert result.decision is AdmissionDecision.REFUSED
    assert any("forged author" in r for r in result.reasons)


def test_governance_block_signed_by_identity_less_key_is_refused():
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-no-identity", pub, frozenset({"GovernanceBlock"}), frozenset({"policy-author"}),
        # no identity=
    )
    issuer = dev_issuer("key-no-identity", "policy:author-1", priv)
    signed = sign_governance_block(
        GOVERNANCE, key_id=issuer.key_id, identity=issuer.identity, sign=issuer.sign,
    )
    plan = _plan(GOVERNANCE, maker_id="maker-1")

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=trust_store,
        signed_governance_block=signed, policy_author_role="policy-author", now=NOW,
    )
    assert result.decision is AdmissionDecision.REFUSED
    assert any("cannot vouch for a policy author" in r for r in result.reasons)


# --- 6. StageReceipt issuer mismatch ---------------------------------------

def test_stage_receipt_issuer_mismatch_fails_verification():
    """The self-declared envelope `issuer` field on a StageReceipt must
    equal the signing key's bound identity -- a key correctly authorized
    for the StageReceipt type AND role can still not claim to be issued by
    an arbitrary principal string."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-stage-1", pub, frozenset({"StageReceipt"}), frozenset({"evidence-grounder"}),
        identity="issuer:evidence-grounder",
    )
    receipt = {
        "schema_version": "1.0.0",
        "type": "StageReceipt",
        "issuer": "issuer:someone-else",  # forged -- does not match bound identity
        "issued_at": "2026-09-16T00:00:00+00:00",
        "expires_at": FAR_FUTURE,
        "run_id": "run-1",
        "nonce": "nonce-1",
        "key_id": "key-stage-1",
        "role": "evidence-grounder",
        "capability": "tool:ingest_text",
        "status": "SATISFIED",
        "action_digest": "a" * 64,
        "input_digest": "input-1",
        "output_digest": "output-1",
        "reason": "",
    }
    signed = _stamp_and_sign(receipt, priv)

    result = verify(signed, "StageReceipt", trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("issuer identity" in e for e in result.errors)

    # Sanity: the identical receipt with the correct issuer DOES verify --
    # proves the rejection above is about identity, not some other field.
    matching = dict(receipt)
    matching["issuer"] = "issuer:evidence-grounder"
    matching = _stamp_and_sign(matching, priv)
    ok_result = verify(matching, "StageReceipt", trust_store=trust_store, now=NOW)
    assert ok_result.ok, ok_result.errors


# --- 7. tampered/unbound/digest-mismatched governance block -> REFUSED,
# not REVIEW_REQUIRED (FIX 3 vocabulary) ------------------------------------

def test_tampered_governance_block_is_refused_not_review_required():
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-author", pub, frozenset({"GovernanceBlock"}), frozenset({"policy-author"}),
        identity="policy:author-1",
    )
    issuer = dev_issuer("key-author", "policy:author-1", priv)
    signed = sign_governance_block(GOVERNANCE, key_id=issuer.key_id, identity=issuer.identity, sign=issuer.sign)
    tampered_governance = GovernanceBlock.from_dict({
        "actions": [{"kind": "edit"}, {"kind": "wipe-everything"}],
    })
    plan = _plan(tampered_governance, maker_id="maker-1")

    result = admit(
        plan, [], governance=tampered_governance, trust_store=trust_store,
        signed_governance_block=signed, policy_author_role="policy-author", now=NOW,
    )
    assert result.decision is AdmissionDecision.REFUSED
    assert result.decision is not AdmissionDecision.REVIEW_REQUIRED


def test_unbound_key_governance_block_is_refused_not_review_required():
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    # registered, but NOT authorized for the GovernanceBlock object type.
    trust_store.add(
        "key-author", pub, frozenset({"StageReceipt"}), frozenset({"policy-author"}),
        identity="policy:author-1",
    )
    issuer = dev_issuer("key-author", "policy:author-1", priv)
    signed = sign_governance_block(GOVERNANCE, key_id=issuer.key_id, identity=issuer.identity, sign=issuer.sign)
    plan = _plan(GOVERNANCE, maker_id="maker-1")

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=trust_store,
        signed_governance_block=signed, policy_author_role="policy-author", now=NOW,
    )
    assert result.decision is AdmissionDecision.REFUSED
    assert result.decision is not AdmissionDecision.REVIEW_REQUIRED
