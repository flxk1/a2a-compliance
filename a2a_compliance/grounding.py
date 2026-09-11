"""Compliance-fleet grounding — derive a steer/hold/escalate from the value graph (SPEC §4).

Given (a) a maker's proposed action / reported state and (b) a compiled policy (the
``policy-compiler`` ``to_grounding_seam()`` payload), produce a per-dimension grounded
finding and fold it into:

  * the envelope ``grounding`` block (populated when any plane is present; ``None`` in
    bare mode — exactly Phase-1), and
  * a recommended control action: ``no-steer`` / ``steer`` / ``hold`` / ``route-human``.

Decision mapping (SPEC §4.1 verdict->steer, plus the specific cases):

  * a prohibition collision (deontic) or a gamed proxy -> ``hold`` (block the action)
  * over the escalation ceiling                        -> ``route-human`` (reserved)
  * a mandate divergence or a norm breach              -> ``steer`` (correct in-boundary)
  * any remaining OPEN, applicable dimension           -> ``route-human`` (fail-closed;
    OPEN is never treated as success)
  * all grounded, applicable dimensions SATISFIED      -> ``no-steer``

Import-safe: this module imports only ``interfaces`` and ``planes`` at load; no
``loomground_*`` / ``deontic`` import happens until a present plane is actually consumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from interfaces.a2a_control import Grounding, PlaneFinding, SteerVerdict
from . import planes as P
from .planes import ALL_PLANES, DimensionFinding

ACTION_NO_STEER = "no-steer"
ACTION_STEER = "steer"
ACTION_HOLD = "hold"
ACTION_ROUTE_HUMAN = "route-human"


@dataclass
class GroundingContext:
    """The universal subject a compliance agent grounds against. Every field is
    optional; a plane with no relevant input reports a not-applicable finding rather
    than a problem. ``policy`` is a ``policy-compiler`` ``to_grounding_seam()`` payload
    (the compile->ground handoff); ``policy_text`` is the raw prose the norm plane reads."""

    maker_id: str = ""
    proposed_action: Optional[dict] = None      # {"bearer","action","condition"?}
    policy: Optional[dict] = None               # to_grounding_seam() payload
    policy_text: Optional[str] = None           # raw prose (for the norm plane)
    mandate: Optional[dict] = None              # {"purpose"|"purposes","evidence"?}
    trajectory: Optional[list] = None           # [{"step","serves","defeats","grounded"?}]
    claims: Optional[list] = None               # [{"claim","falsifiability"?}]
    autonomy: Optional[dict] = None             # {"requested","delegated"?,"factors","ladder"?}
    proxies: Optional[list] = None              # [{"metric","stands_for","metric_movement","value_movement"}]

    @classmethod
    def from_report_state(
        cls, maker_id: str, report_body: dict, *,
        policy: Optional[dict] = None, policy_text: Optional[str] = None,
        proposed_action: Optional[dict] = None, autonomy: Optional[dict] = None,
        proxies: Optional[list] = None,
    ) -> "GroundingContext":
        """Build a context from a maker's ``report-state`` body plus the operator's
        compiled policy and any out-of-band signals (autonomy request, proxy readings)."""
        return cls(
            maker_id=maker_id,
            proposed_action=proposed_action,
            policy=policy,
            policy_text=policy_text,
            mandate=report_body.get("mandate"),
            trajectory=report_body.get("trajectory"),
            claims=report_body.get("claims"),
            autonomy=autonomy,
            proxies=proxies,
        )


@dataclass
class GroundingResult:
    """The fleet's derivation: per-dimension findings, the envelope grounding block
    (``None`` in bare mode), and the recommended control action + its reason."""

    findings: list[DimensionFinding]
    grounding: Optional[Grounding]
    recommended_action: str
    reason: str
    directive: Optional[dict] = field(default=None)

    def provenance(self) -> dict[str, str]:
        """Honest per-dimension provenance read (grounded-via-<plane> vs advisory-absent)."""
        return {f.dimension: f.provenance for f in self.findings}

    @property
    def any_grounded(self) -> bool:
        return any(f.grounded for f in self.findings)


def accept_compiled_policy(seam_payload: dict) -> dict:
    """Accept a ``policy-compiler`` ``to_grounding_seam()`` payload as the fleet's norm
    base. Validates the shape lightly and returns it unchanged; the fleet grounds a
    maker action against these compiled O/P/F norms via the deontic plane."""
    if not isinstance(seam_payload, dict) or "norms" not in seam_payload:
        raise ValueError("not a policy-compiler grounding-seam payload (no 'norms')")
    return seam_payload


def _fold(findings: list[DimensionFinding]) -> SteerVerdict:
    """OPEN-dominant weakest-link fold over the grounded, applicable dimensions."""
    applicable = [f for f in findings if f.grounded and f.applicable]
    if any(f.verdict is SteerVerdict.NOT_SATISFIED for f in applicable):
        return SteerVerdict.NOT_SATISFIED
    if any(f.verdict is SteerVerdict.OPEN for f in applicable):
        return SteerVerdict.OPEN
    return SteerVerdict.SATISFIED


def _grounding_block(ctx: GroundingContext, findings: list[DimensionFinding]) -> Optional[Grounding]:
    """The envelope grounding block. ``None`` when NO plane is present (bare mode =>
    Phase-1 advisory, grounding null). Otherwise every dimension is listed with its
    own provenance, so partial grounding is visible on the wire."""
    if not any(f.grounded for f in findings):
        return None
    plane_findings = [
        PlaneFinding(
            plane=f.dimension,
            verdict=f.verdict,
            detail={
                **f.detail,
                "provenance": f.provenance,
                "reason": f.reason,
                "applicable": f.applicable,
            },
        )
        for f in findings
    ]
    criterion_ref = None
    if ctx.policy:
        criterion_ref = ctx.policy.get("protocol")
    return Grounding(verdict=_fold(findings), planes=plane_findings, criterion_ref=criterion_ref)


def _decide(findings: list[DimensionFinding]) -> tuple[str, str]:
    """Map the grounded findings onto a control action (SPEC §4.1 + the specific cases)."""
    grounded = [f for f in findings if f.grounded]

    for f in grounded:  # a forbidden or gamed action must be stopped
        if f.verdict is SteerVerdict.NOT_SATISFIED and f.dimension in ("deontic", "proxy"):
            return ACTION_HOLD, f.reason
    for f in grounded:  # over the autonomy ceiling -> reserved, route to human
        if f.verdict is SteerVerdict.NOT_SATISFIED and f.dimension == "escalation":
            return ACTION_ROUTE_HUMAN, f.reason
    for f in grounded:  # correctable within the declared boundary
        if f.verdict is SteerVerdict.NOT_SATISFIED and f.dimension in ("mandate", "norm"):
            return ACTION_STEER, f.reason
    for f in grounded:  # unassessed but applicable -> escalate (never a silent pass)
        if f.verdict is SteerVerdict.OPEN and f.applicable:
            return ACTION_ROUTE_HUMAN, f.reason
    return ACTION_NO_STEER, "all grounded, applicable dimensions satisfied"


def ground(ctx: GroundingContext, planes: tuple[str, ...] = ALL_PLANES) -> GroundingResult:
    """Derive the grounded criterion + recommended action. NEVER raises because a plane
    is absent: each dimension degrades independently to its advisory fallback."""
    findings = [P.assess(plane, ctx) for plane in planes]
    grounding = _grounding_block(ctx, findings)
    action, reason = _decide(findings)

    directive: Optional[dict] = None
    if action == ACTION_STEER:
        directive = {"instruction": reason, "kind": "constrain", "reason_ref": "grounded"}
    elif action == ACTION_HOLD:
        directive = {"scope": "next-action", "reason_ref": "grounded", "reason": reason}

    return GroundingResult(
        findings=findings, grounding=grounding,
        recommended_action=action, reason=reason, directive=directive,
    )
