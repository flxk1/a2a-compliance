"""Effect comparison belongs to the effect-reconciliation plane, not to lifecycle.

`lifecycle.reconcile` folds postflight *receipts*. The intended-versus-observed
comparison is the `effect-reconciliation` plane's computation and reaches a2a
only as a role-owned receipt (`tool:effect_reconcile`). The plane is a host
capability, never an import -- a2a hard-depends on no plane -- so the guard has
two halves: the declaration names the plane as the owner, and the fold's verdict
turns on the plane's receipt rather than on any effect bytes a2a can see.

Without this, a later "consolidation" could move the comparison into
lifecycle.py and nothing would fail.
"""

import sys

from a2a_compliance import (
    ACTION_NO_STEER,
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

PLANE_REPO = "effect-reconciliation"
PLANE_TOOL = "effect_reconcile"

OWNERS = {
    capability.name: role.id
    for role in TEAM_ROLES
    for capability in role.capabilities
    if capability.kind.value == "tool"
}


def _plan():
    tools, skills, contracts, distributions = set(), set(), set(), set()
    for role in TEAM_ROLES:
        for cap in role.capabilities:
            {"tool": tools, "skill": skills, "contract": contracts,
             "distribution": distributions}[cap.kind.value].add(cap.name)
    inventory = CapabilityInventory.from_iterables(
        tools=tools, skills=skills, contracts=contracts, distributions=distributions,
    )
    request = ControlRequest(
        GroundingContext(maker_id="maker-1",
                         proposed_action={"bearer": "maker-1", "action": "edit module X"}),
        "edit",
        GovernanceBlock.from_dict({"actions": [{"kind": "edit"}]}),
    )
    return ComplianceTeam(inventory).assess(
        request, GroundingResult([], None, ACTION_NO_STEER, "test result"),
    )


def _receipts(plan, names):
    return [
        StageReceipt(
            role=OWNERS[name], capability=f"tool:{name}",
            status=ReceiptStatus.SATISFIED, action_digest=plan.action_digest,
            input_digest=f"input-{name}", output_digest=f"output-{name}",
        )
        for name in names
    ]


def test_effect_comparison_is_declared_as_the_planes_tool():
    declared = [
        (role.id, cap) for role in TEAM_ROLES for cap in role.capabilities
        if cap.name == PLANE_TOOL
    ]
    assert len(declared) == 1, "effect comparison must have exactly one declared owner"
    role_id, capability = declared[0]
    assert capability.repo == PLANE_REPO
    assert capability.required is True
    assert capability.kind.value == "tool"
    assert role_id == "assurance-recorder"
    assert PLANE_TOOL in POSTFLIGHT_TOOLS


def test_certification_fails_closed_without_the_planes_receipt():
    plan = _plan()
    preview = enforce_preview(plan, _receipts(plan, PREFLIGHT_TOOLS))
    control = ControlReceipt(plan.action_digest, "dispatch-1", "effects-1")
    without = [name for name in POSTFLIGHT_TOOLS if name != PLANE_TOOL]

    result = reconcile(plan, preview, control, _receipts(plan, without))
    assert result.certified is False
    assert result.state is RunState.RECONCILED
    assert result.missing_receipts == (PLANE_TOOL,)

    complete = reconcile(plan, preview, control, _receipts(plan, POSTFLIGHT_TOOLS))
    assert complete.certified is True
    assert complete.state is RunState.CERTIFIED


def test_the_fold_compares_no_effects_of_its_own():
    # The verdict is invariant under the observed-effects digest: lifecycle never
    # reads it, because it does not compare effects. The evidence that effects
    # matched is the plane's receipt (asserted above), not this field.
    plan = _plan()
    preview = enforce_preview(plan, _receipts(plan, PREFLIGHT_TOOLS))
    receipts = _receipts(plan, POSTFLIGHT_TOOLS)
    verdicts = {
        reconcile(plan, preview,
                  ControlReceipt(plan.action_digest, "dispatch-1", digest),
                  receipts).certified
        for digest in ("effects-1", "effects-2-completely-different", "")
    }
    assert verdicts == {True}


def test_the_plane_is_consumed_as_a_capability_never_as_an_import():
    plan = _plan()
    preview = enforce_preview(plan, _receipts(plan, PREFLIGHT_TOOLS))
    reconcile(plan, preview, ControlReceipt(plan.action_digest, "d", "e"),
              _receipts(plan, POSTFLIGHT_TOOLS))
    assert "effect_reconciliation" not in sys.modules
