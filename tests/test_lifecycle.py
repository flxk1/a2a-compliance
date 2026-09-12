import pytest

from a2a_compliance import (
    ACTION_NO_STEER,
    ACTION_STEER,
    CapabilityInventory,
    ComplianceTeam,
    ControlReceipt,
    ControlRequest,
    GovernanceBlock,
    GroundingContext,
    GroundingResult,
    POSTFLIGHT_TOOLS,
    PREFLIGHT_TOOLS,
    ReceiptStatus,
    RunState,
    StageReceipt,
    TEAM_ROLES,
    enforce_preview,
    reconcile,
)


OWNERS = {
    capability.name: role.id
    for role in TEAM_ROLES
    for capability in role.capabilities
    if capability.kind.value == "tool"
}


def _plan(action=ACTION_NO_STEER):
    tools, skills, contracts, distributions = set(), set(), set(), set()
    for role in TEAM_ROLES:
        for cap in role.capabilities:
            {"tool": tools, "skill": skills, "contract": contracts,
             "distribution": distributions}[cap.kind.value].add(cap.name)
    inventory = CapabilityInventory.from_iterables(
        tools=tools, skills=skills, contracts=contracts, distributions=distributions,
    )
    request = ControlRequest(
        GroundingContext(
            maker_id="maker-1",
            proposed_action={"bearer": "maker-1", "action": "edit module X"},
        ),
        "edit",
        GovernanceBlock.from_dict({"actions": [{"kind": "edit"}]}),
    )
    result = GroundingResult([], None, action, "test result")
    return ComplianceTeam(inventory).assess(request, result)


def _receipts(plan, names, status=ReceiptStatus.SATISFIED):
    return [
        StageReceipt(
            role=OWNERS[name], capability=f"tool:{name}", status=status,
            action_digest=plan.action_digest,
            input_digest=f"input-{name}", output_digest=f"output-{name}",
            reason="not applicable to this action" if status is ReceiptStatus.NOT_APPLICABLE else "",
        )
        for name in names
    ]


def test_action_digest_is_deterministic_and_binds_the_proposed_action():
    assert _plan().action_digest == _plan().action_digest
    assert len(_plan().action_digest) == 64


def test_full_profile_needs_every_preflight_receipt_before_admission():
    plan = _plan()
    preview = enforce_preview(plan, _receipts(plan, PREFLIGHT_TOOLS[:-1]))
    assert preview.state is RunState.ROUTED_HUMAN
    assert preview.missing_receipts == (PREFLIGHT_TOOLS[-1],)
    assert preview.dispatch_performed is False


def test_satisfied_preflight_admits_but_never_dispatches():
    plan = _plan()
    preview = enforce_preview(plan, _receipts(plan, PREFLIGHT_TOOLS))
    assert preview.state is RunState.ADMITTED
    assert preview.admitted is True
    assert preview.dispatch_performed is False


@pytest.mark.parametrize(
    ("status", "expected"),
    [(ReceiptStatus.OPEN, RunState.ROUTED_HUMAN),
     (ReceiptStatus.ERROR, RunState.ROUTED_HUMAN),
     (ReceiptStatus.NOT_SATISFIED, RunState.HELD)],
)
def test_strictest_preflight_receipt_controls_the_preview(status, expected):
    plan = _plan()
    receipts = _receipts(plan, PREFLIGHT_TOOLS)
    receipts[-1] = _receipts(plan, (PREFLIGHT_TOOLS[-1],), status)[0]
    assert enforce_preview(plan, receipts).state is expected


def test_role_and_action_digest_mismatches_route_human():
    plan = _plan()
    receipts = _receipts(plan, PREFLIGHT_TOOLS)
    receipts[0] = StageReceipt(
        role="decision-verifier", capability="tool:ingest_text",
        status=ReceiptStatus.SATISFIED, action_digest="wrong",
        input_digest="i", output_digest="o",
    )
    preview = enforce_preview(plan, receipts)
    assert preview.state is RunState.ROUTED_HUMAN
    assert preview.invalid_receipts == ("ingest_text:action-digest-mismatch",)


def test_not_applicable_needs_an_explicit_reason():
    plan = _plan()
    with pytest.raises(ValueError, match="requires a reason"):
        StageReceipt(
            role=OWNERS["topos_parse"], capability="tool:topos_parse",
            status=ReceiptStatus.NOT_APPLICABLE, action_digest=plan.action_digest,
            input_digest="i",
        )


def test_corrective_grounding_holds_original_action_before_receipt_fold():
    preview = enforce_preview(_plan(ACTION_STEER), ())
    assert preview.state is RunState.HELD
    assert preview.admitted is False


def test_reconciliation_consumes_postflight_receipts_and_certifies():
    plan = _plan()
    preview = enforce_preview(plan, _receipts(plan, PREFLIGHT_TOOLS))
    control = ControlReceipt(plan.action_digest, "dispatch-1", "effects-1")
    incomplete = reconcile(plan, preview, control, _receipts(plan, POSTFLIGHT_TOOLS[:-1]))
    assert incomplete.state is RunState.RECONCILED
    assert incomplete.certified is False
    assert incomplete.missing_receipts == (POSTFLIGHT_TOOLS[-1],)

    complete = reconcile(plan, preview, control, _receipts(plan, POSTFLIGHT_TOOLS))
    assert complete.state is RunState.CERTIFIED
    assert complete.certified is True


def test_human_approved_dispatch_also_requires_oversight_verification():
    plan = _plan()
    preview = enforce_preview(plan, _receipts(plan, PREFLIGHT_TOOLS))
    control = ControlReceipt(plan.action_digest, "dispatch-1", "effects-1", "approval-1")
    result = reconcile(plan, preview, control, _receipts(plan, POSTFLIGHT_TOOLS))
    assert result.certified is False
    assert result.missing_receipts == ("oversight_verify",)


def test_reconciliation_refuses_a_dispatch_without_admission():
    plan = _plan(ACTION_STEER)
    preview = enforce_preview(plan, ())
    control = ControlReceipt(plan.action_digest, "dispatch-1", "effects-1")
    result = reconcile(plan, preview, control, _receipts(plan, POSTFLIGHT_TOOLS))
    assert result.state is RunState.ROUTED_HUMAN
    assert result.invalid_receipts == ("enforcement-preview:not-admitted",)
