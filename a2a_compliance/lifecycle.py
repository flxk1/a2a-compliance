"""Receipt-gated lifecycle around a compliance plan.

The lifecycle consumes verdict receipts produced by existing Loomground tools.
It does not reproduce their checks and it never performs the action it admits.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from .grounding import ACTION_HOLD, ACTION_NO_STEER, ACTION_ROUTE_HUMAN, ACTION_STEER
from .team import COMPLIANCE_ROLES, CapabilityKind, ControlPlan, TeamProfile


class ReceiptStatus(str, Enum):
    SATISFIED = "SATISFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_SATISFIED = "NOT_SATISFIED"
    OPEN = "OPEN"
    ERROR = "ERROR"


class RunState(str, Enum):
    PLANNED = "PLANNED"
    ASSESSED = "ASSESSED"
    ADMITTED = "ADMITTED"
    HELD = "HELD"
    ROUTED_HUMAN = "ROUTED_HUMAN"
    REFUSED = "REFUSED"
    DISPATCHED = "DISPATCHED"
    RECONCILED = "RECONCILED"
    CERTIFIED = "CERTIFIED"


# Tools that must report before the full-profile host may dispatch.  Erasure is
# excluded: it is a separately authorised effect, never a routine preflight.
PREFLIGHT_TOOLS: tuple[str, ...] = (
    "ingest_text", "versum_index",
    "policy_compile", "policy_check",
    "factual_lower", "epistemic_extract", "deontic_parse", "deontic_conflicts",
    "topos_parse", "norm_extract",
    "solver_evaluate", "solver_verify",
    "brief", "collapse", "escalation", "falsifiability", "mandate", "proxy",
    "lane_evaluate", "lock_text", "drift_breaker", "privacy_scan",
)

POSTFLIGHT_TOOLS: tuple[str, ...] = (
    "govcert_verify", "nd_digest", "enforcement_compare", "effect_reconcile",
    "norm_freshness", "obligation_admit", "audit_chain_verify",
    "evidence_emit", "evidence_verify",
)

TOOL_OWNERS = {
    capability.name: role.id
    for role in COMPLIANCE_ROLES
    for capability in role.capabilities
    if capability.kind is CapabilityKind.TOOL
}


@dataclass(frozen=True)
class StageReceipt:
    role: str
    capability: str
    status: ReceiptStatus
    action_digest: str
    input_digest: str
    output_digest: Optional[str] = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status is ReceiptStatus.NOT_APPLICABLE and not self.reason.strip():
            raise ValueError("NOT_APPLICABLE receipt requires a reason")
        if self.status is ReceiptStatus.SATISFIED and not self.output_digest:
            raise ValueError("SATISFIED receipt requires an output_digest")


@dataclass(frozen=True)
class EnforcementPreview:
    state: RunState
    decision: str
    admitted: bool
    action_digest: str
    missing_receipts: tuple[str, ...] = ()
    open_receipts: tuple[str, ...] = ()
    failed_receipts: tuple[str, ...] = ()
    invalid_receipts: tuple[str, ...] = ()
    reason: str = ""
    dispatch_performed: bool = False


@dataclass(frozen=True)
class ControlReceipt:
    action_digest: str
    dispatch_id: str
    observed_effects_digest: str
    human_approval_ref: Optional[str] = None


@dataclass(frozen=True)
class Reconciliation:
    state: RunState
    certified: bool
    action_digest: str
    missing_receipts: tuple[str, ...] = ()
    open_receipts: tuple[str, ...] = ()
    failed_receipts: tuple[str, ...] = ()
    invalid_receipts: tuple[str, ...] = ()
    reason: str = ""


def _index(
    action_digest: str, receipts: Iterable[StageReceipt],
) -> tuple[dict[str, StageReceipt], tuple[str, ...]]:
    indexed: dict[str, StageReceipt] = {}
    invalid: list[str] = []
    for receipt in receipts:
        key = receipt.capability.removeprefix("tool:")
        if receipt.action_digest != action_digest:
            invalid.append(f"{key}:action-digest-mismatch")
        elif TOOL_OWNERS.get(key) != receipt.role:
            invalid.append(f"{key}:role-mismatch")
        elif key in indexed:
            invalid.append(f"{key}:duplicate")
        else:
            indexed[key] = receipt
    return indexed, tuple(invalid)


def _receipt_findings(
    required: tuple[str, ...], indexed: dict[str, StageReceipt],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    missing = tuple(name for name in required if name not in indexed)
    opened = tuple(name for name in required if name in indexed and indexed[name].status in {
        ReceiptStatus.OPEN, ReceiptStatus.ERROR,
    })
    failed = tuple(name for name in required if name in indexed and
                   indexed[name].status is ReceiptStatus.NOT_SATISFIED)
    return missing, opened, failed


def enforce_preview(
    plan: ControlPlan, receipts: Iterable[StageReceipt] = (),
) -> EnforcementPreview:
    """Fold preflight receipts without dispatching or mutating anything."""
    if plan.disposition == "refuse":
        return EnforcementPreview(RunState.REFUSED, "refuse", False,
                                  plan.action_digest, reason=plan.ruling.reason)
    if plan.ruling.decision.value == ACTION_ROUTE_HUMAN:
        return EnforcementPreview(RunState.ROUTED_HUMAN, ACTION_ROUTE_HUMAN, False,
                                  plan.action_digest, reason=plan.ruling.reason)
    if not plan.ready:
        return EnforcementPreview(RunState.ROUTED_HUMAN, ACTION_ROUTE_HUMAN, False,
                                  plan.action_digest,
                                  reason="plan is not ready for orchestration")
    if plan.recommended_action == ACTION_ROUTE_HUMAN:
        return EnforcementPreview(RunState.ROUTED_HUMAN, ACTION_ROUTE_HUMAN, False,
                                  plan.action_digest,
                                  reason="grounding requires human review")
    if plan.recommended_action in {ACTION_HOLD, ACTION_STEER}:
        return EnforcementPreview(RunState.HELD, ACTION_HOLD, False,
                                  plan.action_digest,
                                  reason="maker action requires correction before admission")

    required = PREFLIGHT_TOOLS if plan.profile is TeamProfile.LOOMGROUND else ()
    indexed, invalid = _index(plan.action_digest, receipts)
    missing, opened, failed = _receipt_findings(required, indexed)
    if invalid or opened or missing:
        return EnforcementPreview(
            RunState.ROUTED_HUMAN, ACTION_ROUTE_HUMAN, False, plan.action_digest,
            missing, opened, failed, invalid,
            "preflight is incomplete, open, erroneous, duplicated or unbound",
        )
    if failed:
        return EnforcementPreview(
            RunState.HELD, ACTION_HOLD, False, plan.action_digest,
            missing, opened, failed, invalid,
            "one or more preflight controls are not satisfied",
        )
    return EnforcementPreview(
        RunState.ADMITTED, "admitted", True, plan.action_digest,
        reason=("all required preflight receipts satisfied or explicitly not applicable"
                if required else "protocol profile admitted on role authority"),
    )


def reconcile(
    plan: ControlPlan, preview: EnforcementPreview, control: ControlReceipt,
    receipts: Iterable[StageReceipt],
) -> Reconciliation:
    """Consume postflight receipts; do not perform effect comparison locally."""
    if not preview.admitted or preview.state is not RunState.ADMITTED:
        return Reconciliation(
            RunState.ROUTED_HUMAN, False, plan.action_digest,
            invalid_receipts=("enforcement-preview:not-admitted",),
            reason="a dispatch cannot be reconciled as compliant without admission",
        )
    if preview.action_digest != plan.action_digest or control.action_digest != plan.action_digest:
        return Reconciliation(
            RunState.ROUTED_HUMAN, False, plan.action_digest,
            invalid_receipts=("lifecycle:action-digest-mismatch",),
            reason="preview or dispatch receipt is not bound to this plan",
        )
    required = list(POSTFLIGHT_TOOLS if plan.profile is TeamProfile.LOOMGROUND else ())
    if control.human_approval_ref:
        required.append("oversight_verify")
    indexed, invalid = _index(plan.action_digest, receipts)
    missing, opened, failed = _receipt_findings(tuple(required), indexed)
    if invalid or missing or opened or failed:
        return Reconciliation(
            RunState.RECONCILED, False, plan.action_digest,
            missing, opened, failed, invalid,
            "postflight evidence is incomplete or not satisfied",
        )
    return Reconciliation(
        RunState.CERTIFIED, True, plan.action_digest,
        reason="all required postflight receipts satisfied or explicitly not applicable",
    )
