"""E2 conformance suite: verified admission + permit issuance
(`a2a_compliance.wire.admission`). Every signed object here is built by the
TEST-ONLY dev signer (`wire.dev_sign_subject`) over ephemeral dev keypairs
generated in-process -- never a production key, exactly like
`tests/vectors/e1/`. Trust bindings are deployment config, injected the same
way a host would, never read from a vector's own payload.
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
from a2a_compliance.lifecycle import TOOL_OWNERS, PREFLIGHT_TOOLS
from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import (
    AdmissionDecision,
    InMemoryApproverAuthority,
    admit,
    dev_issuer,
    issue_permit,
)
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import ANY, InMemoryTrustStore
from a2a_compliance.wire.verification import InMemoryNonceStore, verify

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
FAR_FUTURE = "2099-01-01T00:00:00+00:00"
PAST = "2020-01-01T00:00:00+00:00"


# --- plan construction -------------------------------------------------

def _full_inventory():
    tools, skills, contracts, distributions = set(), set(), set(), set()
    for role in TEAM_ROLES:
        for cap in role.capabilities:
            {"tool": tools, "skill": skills, "contract": contracts,
             "distribution": distributions}[cap.kind.value].add(cap.name)
    return CapabilityInventory.from_iterables(
        tools=tools, skills=skills, contracts=contracts, distributions=distributions,
    )


def _plan(target_kind, governance, *, action=ACTION_NO_STEER):
    request = ControlRequest(
        GroundingContext(maker_id="maker-1", proposed_action={"bearer": "maker-1", "action": target_kind}),
        target_kind,
        governance,
    )
    result = GroundingResult([], None, action, "test result")
    return ComplianceTeam(_full_inventory()).assess(request, result)


NORMAL_GOVERNANCE = GovernanceBlock.from_dict({"actions": [{"kind": "edit"}]})
RESERVED_GOVERNANCE = GovernanceBlock.from_dict({
    "actions": [{"kind": "edit"}],
    "reserved": [{"kind": "delete-prod-data", "by": "human"}],
})
PROHIBITED_GOVERNANCE = GovernanceBlock.from_dict({
    "actions": [{"kind": "edit"}],
    "prohibited": ["wipe-everything"],
})
OBLIGATION_GOVERNANCE = GovernanceBlock.from_dict({
    "actions": [{"kind": "edit"}], "obligations": ["record_effects"],
})


# --- signing helpers -----------------------------------------------------

def _stamp_and_sign(obj: dict, priv: bytes) -> dict:
    obj = dict(obj)
    obj["subject_digest"] = canonical.subject_digest(obj)
    obj["signature"] = dev_sign_subject(obj, priv)
    return obj


def _stage_receipt(plan, name, priv, key_id, *, status="SATISFIED", **overrides):
    base = {
        "schema_version": "1.0.0",
        "type": "StageReceipt",
        "issuer": f"issuer:{TOOL_OWNERS[name]}",
        "issued_at": "2026-09-16T00:00:00+00:00",
        "expires_at": FAR_FUTURE,
        "run_id": "run-e2-0001",
        "nonce": f"nonce-{name}",
        "key_id": key_id,
        "role": TOOL_OWNERS[name],
        "capability": f"tool:{name}",
        "status": status,
        "action_digest": plan.action_digest,
        "input_digest": f"input-{name}",
        "output_digest": (f"output-{name}" if status == "SATISFIED" else None),
        "reason": "not applicable to this action" if status == "NOT_APPLICABLE" else "",
    }
    base.update(overrides)
    return _stamp_and_sign(base, priv)


def _all_preflight(plan, priv, key_id):
    return [_stage_receipt(plan, name, priv, key_id) for name in PREFLIGHT_TOOLS]


def _approval(plan, priv, key_id, *, approver_id="human-1", approver_role="rung-2",
              scope="next-action", reservations=(), **overrides):
    base = {
        "schema_version": "1.0.0",
        "type": "HumanApprovalReceipt",
        "issuer": f"issuer:{approver_id}",
        "issued_at": "2026-09-16T00:00:00+00:00",
        "expires_at": FAR_FUTURE,
        "run_id": "run-e2-0001",
        "nonce": "nonce-approval-0001",
        "key_id": key_id,
        "approver": {"id": approver_id, "role": approver_role},
        "permitted_action_digest": plan.action_digest,
        "scope": scope,
        "reservations": list(reservations),
    }
    base.update(overrides)
    return _stamp_and_sign(base, priv)


@pytest.fixture()
def keys():
    return {
        "stage": generate_dev_keypair(),
        "approver": generate_dev_keypair(),
        "approver_wrong_role": generate_dev_keypair(),
        "issuer": generate_dev_keypair(),
        "forger": generate_dev_keypair(),
    }


def _trust_store(keys):
    store = InMemoryTrustStore()
    store.add("key-stage", keys["stage"][1], frozenset({"StageReceipt"}), frozenset({ANY}))
    store.add("key-approver", keys["approver"][1], frozenset({"HumanApprovalReceipt"}), frozenset())
    store.add("key-approver-wrong-role", keys["approver_wrong_role"][1],
              frozenset({"HumanApprovalReceipt"}), frozenset())
    store.add("key-issuer", keys["issuer"][1], frozenset({"ExecutionPermit"}), frozenset())
    # key-forger is deliberately NOT registered under its own key_id.
    return store


def _authority():
    authority = InMemoryApproverAuthority()
    authority.allow("delete-prod-data", "rung-2")
    return authority


# --- prohibited: never admits, even with a valid approval -----------------

def test_prohibited_kind_is_refused_even_with_a_valid_approval(keys):
    plan = _plan("wipe-everything", PROHIBITED_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver")
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=PROHIBITED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert result.decision is AdmissionDecision.REFUSED
    assert "prohibited" in result.reasons[0]


def test_undeclared_kind_is_refused(keys):
    plan = _plan("some-undeclared-kind", NORMAL_GOVERNANCE)
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW,
    )
    assert result.decision is AdmissionDecision.REFUSED


# --- reserved: admits only with a scoped, matching, authorized approval ---

def test_reserved_kind_without_approval_is_review_required(keys):
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approver_authority=_authority(), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("requires a HumanApprovalReceipt" in r for r in result.reasons)


def test_reserved_kind_with_wrong_digest_approval_is_review_required(keys):
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    other_plan = _plan("edit", NORMAL_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver",
                          permitted_action_digest=other_plan.action_digest)
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("permitted_action_digest mismatch" in r for r in result.reasons)


def test_reserved_kind_with_expired_approval_is_review_required(keys):
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver", expires_at=PAST)
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("approval receipt failed verification" in r for r in result.reasons)


def test_reserved_kind_with_unauthorized_approver_is_review_required(keys):
    # rung-0 is never authorized for any kind in this authority.
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver", approver_role="rung-0")
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("not authorized for reserved kind" in r for r in result.reasons)


def test_reserved_kind_out_of_scope_approver_is_review_required(keys):
    # A legitimate rung-2 approver, but the authority never granted rung-2
    # for THIS kind -- authorized for a different reserved kind entirely.
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    authority = InMemoryApproverAuthority()
    authority.allow("some-other-reserved-kind", "rung-2")
    approval = _approval(plan, keys["approver"][0], "key-approver")
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=authority, now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("not authorized for reserved kind" in r for r in result.reasons)


def test_reserved_kind_with_forged_signature_approval_is_review_required(keys):
    # Claims key_id "key-approver" (a registered, authorized key) but is
    # actually signed by a different, unrelated private key.
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    forged = _approval(plan, keys["approver"][0], "key-approver")
    forged["signature"] = dev_sign_subject(forged, keys["forger"][0])
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=forged, approver_authority=_authority(), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("Ed25519 signature does not verify" in r for r in result.reasons)


def test_reserved_kind_with_valid_approval_admits_even_when_plan_not_ready(keys):
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    assert plan.ready is False, "a ROUTE_HUMAN ruling never makes team.py's plan 'ready'"
    approval = _approval(plan, keys["approver"][0], "key-approver")
    result = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert result.decision is AdmissionDecision.ADMITTED


# --- ready alone never admits; unverified/incomplete receipts block -------

def test_ready_but_incomplete_receipts_never_admits(keys):
    plan = _plan("edit", NORMAL_GOVERNANCE)
    assert plan.ready is True
    receipts = _all_preflight(plan, keys["stage"][0], "key-stage")[:-1]  # one short
    result = admit(
        plan, receipts, governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("missing preflight receipt" in r for r in result.reasons)


def test_no_receipts_at_all_never_admits_even_though_plan_is_ready(keys):
    plan = _plan("edit", NORMAL_GOVERNANCE)
    assert plan.ready is True
    result = admit(plan, [], governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW)
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED


def test_invalid_unverified_stage_receipt_blocks_admission(keys):
    plan = _plan("edit", NORMAL_GOVERNANCE)
    receipts = _all_preflight(plan, keys["stage"][0], "key-stage")
    receipts[0] = dict(receipts[0])
    receipts[0]["input_digest"] = "tampered-after-signing"
    receipts[0]["subject_digest"] = canonical.subject_digest(receipts[0])  # digest re-stamped, signature stale
    result = admit(
        plan, receipts, governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("invalid preflight receipt" in r for r in result.reasons)


def test_duplicate_capability_receipt_blocks_admission(keys):
    plan = _plan("edit", NORMAL_GOVERNANCE)
    receipts = _all_preflight(plan, keys["stage"][0], "key-stage")
    receipts.append(receipts[0])
    result = admit(
        plan, receipts, governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("duplicate receipt" in r for r in result.reasons)


def test_failed_preflight_receipt_blocks_admission(keys):
    plan = _plan("edit", NORMAL_GOVERNANCE)
    receipts = _all_preflight(plan, keys["stage"][0], "key-stage")
    failing_name = PREFLIGHT_TOOLS[-1]
    receipts[-1] = _stage_receipt(plan, failing_name, keys["stage"][0], "key-stage",
                                   status="NOT_SATISFIED")
    result = admit(
        plan, receipts, governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("failed preflight receipt" in r for r in result.reasons)


def test_unacknowledged_obligation_blocks_admission(keys):
    plan = _plan("edit", OBLIGATION_GOVERNANCE)
    receipts = _all_preflight(plan, keys["stage"][0], "key-stage")
    result = admit(
        plan, receipts, governance=OBLIGATION_GOVERNANCE, trust_store=_trust_store(keys), now=NOW,
    )
    assert result.decision is AdmissionDecision.REVIEW_REQUIRED
    assert any("unacknowledged obligation" in r for r in result.reasons)

    acked = admit(
        plan, receipts, governance=OBLIGATION_GOVERNANCE, trust_store=_trust_store(keys),
        acknowledged_obligations=["record_effects"], now=NOW,
    )
    assert acked.decision is AdmissionDecision.ADMITTED


# --- normal (non-reserved) admission --------------------------------------

def test_normal_kind_admits_on_complete_verified_preflight(keys):
    plan = _plan("edit", NORMAL_GOVERNANCE)
    receipts = _all_preflight(plan, keys["stage"][0], "key-stage")
    result = admit(
        plan, receipts, governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW,
    )
    assert result.decision is AdmissionDecision.ADMITTED
    assert result.reasons == ()


# --- permit issuance: only on ADMITTED, signed, single-use nonce ----------

def test_review_required_and_refused_never_issue_a_permit(keys):
    plan = _plan("wipe-everything", PROHIBITED_GOVERNANCE)
    refused = admit(plan, [], governance=PROHIBITED_GOVERNANCE, trust_store=_trust_store(keys), now=NOW)
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        refused, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-e2-0001", nonce="permit-nonce-1",
        expires_at=NOW + timedelta(hours=1), nonce_store=InMemoryNonceStore(),
    )
    assert result.ok is False
    assert result.permit is None

    plan2 = _plan("edit", NORMAL_GOVERNANCE)
    review = admit(plan2, [], governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW)
    result2 = issue_permit(
        review, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-e2-0002", nonce="permit-nonce-2",
        expires_at=NOW + timedelta(hours=1), nonce_store=InMemoryNonceStore(),
    )
    assert result2.ok is False
    assert result2.permit is None


def test_admitted_issues_a_permit_that_e1_verify_accepts_and_nonce_is_single_use(keys):
    plan = _plan("edit", NORMAL_GOVERNANCE)
    receipts = _all_preflight(plan, keys["stage"][0], "key-stage")
    admission = admit(plan, receipts, governance=NORMAL_GOVERNANCE, trust_store=_trust_store(keys), now=NOW)
    assert admission.decision is AdmissionDecision.ADMITTED

    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    nonce_store = InMemoryNonceStore()
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-e2-0001", nonce="permit-nonce-1",
        expires_at=NOW + timedelta(hours=1), nonce_store=nonce_store, issued_at=NOW,
    )
    assert result.ok, result.reasons
    permit = result.permit
    assert permit["action_digest"] == plan.action_digest
    assert permit["enforcement_grade"] == "mediated"
    assert permit["adapter"] == "subprocess"

    trust_store = _trust_store(keys)
    verified = verify(permit, "ExecutionPermit", trust_store=trust_store, now=NOW)
    assert verified.ok, verified.errors

    # the SAME (run_id, nonce) cannot be consumed twice.
    reused = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-e2-0001", nonce="permit-nonce-1",
        expires_at=NOW + timedelta(hours=1), nonce_store=nonce_store, issued_at=NOW,
    )
    assert reused.ok is False
    assert any("nonce reuse" in r for r in reused.reasons)


def test_reserved_kind_permit_carries_forward_reservations(keys):
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver",
                          reservations=["notify-security-team"])
    admission = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert admission.decision is AdmissionDecision.ADMITTED

    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-e2-0001", nonce="permit-nonce-reserved",
        expires_at=NOW + timedelta(hours=1), nonce_store=InMemoryNonceStore(), approval=approval,
    )
    assert result.ok, result.reasons
    assert result.permit["constraints"]["reservations"] == ["notify-security-team"]


def test_caller_supplied_constraints_cannot_shadow_verified_reservations(keys):
    # A host-supplied `constraints["reservations"]` must never hide the
    # verified approver's actual reservations from the issued permit.
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver",
                          reservations=["notify-security-team"])
    admission = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert admission.decision is AdmissionDecision.ADMITTED

    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-e2-0001", nonce="permit-nonce-shadow",
        expires_at=NOW + timedelta(hours=1), nonce_store=InMemoryNonceStore(),
        approval=approval, constraints={"reservations": ["forged-empty-override"]},
    )
    assert result.ok, result.reasons
    assert result.permit["constraints"]["reservations"] == ["notify-security-team"]


def test_issuer_identity_equal_to_approver_identity_is_rejected(keys):
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver", approver_id="same-human")
    admission = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert admission.decision is AdmissionDecision.ADMITTED

    # The issuer claims the SAME identity as the approver -- role separation.
    same_identity_issuer = dev_issuer("key-issuer", "same-human", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=same_identity_issuer, enforcement_grade="mediated",
        adapter="subprocess", run_id="run-e2-0001", nonce="permit-nonce-sep",
        expires_at=NOW + timedelta(hours=1), nonce_store=InMemoryNonceStore(), approval=approval,
    )
    assert result.ok is False
    assert any("role separation" in r for r in result.reasons)


def test_issuer_key_id_equal_to_approver_key_id_is_rejected(keys):
    plan = _plan("delete-prod-data", RESERVED_GOVERNANCE)
    approval = _approval(plan, keys["approver"][0], "key-approver")
    admission = admit(
        plan, _all_preflight(plan, keys["stage"][0], "key-stage"),
        governance=RESERVED_GOVERNANCE, trust_store=_trust_store(keys),
        approval=approval, approver_authority=_authority(), now=NOW,
    )
    assert admission.decision is AdmissionDecision.ADMITTED

    # Different declared identity, but the SAME underlying signing key_id
    # as the approval -- also role separation.
    same_key_issuer = dev_issuer("key-approver", "issuer:enforcement", keys["approver"][0])
    result = issue_permit(
        admission, issuer=same_key_issuer, enforcement_grade="mediated",
        adapter="subprocess", run_id="run-e2-0001", nonce="permit-nonce-sep2",
        expires_at=NOW + timedelta(hours=1), nonce_store=InMemoryNonceStore(), approval=approval,
    )
    assert result.ok is False
    assert any("role separation" in r for r in result.reasons)


# --- bare-install: admission needs jsonschema/cryptography only when the
# caller actually touches it; importing the core package never reaches it
# (see test_bare_install.py -- unaffected by this module's addition).

def test_admission_symbols_are_reachable_only_via_lazy_wire_getattr():
    from a2a_compliance import wire

    assert wire.admit is admit
    assert wire.issue_permit is issue_permit
