"""Per-plane loomground value consumption — universal, optional, per-plane guarded (SPEC §4).

Import-safe: NO ``loomground_*`` / ``deontic`` import at module load. ``available()``
probes with :func:`importlib.util.find_spec`, which does not import the plane (so the
bare path stays loomground-free); the real plane import happens only inside ``assess()``
when the plane is present and actually consumed.

An absent plane degrades that ONE dimension to the Phase-1 advisory/role reading — it
never crashes an op and never fabricates a grounded verdict (SPEC §4.3). A plane that is
present but raises also degrades to advisory for that dimension; other dimensions are
unaffected (each is independent).

Each plane returns the shared solver ``Verdict`` (SATISFIED / NOT_SATISFIED / OPEN),
mapped 1:1 onto :class:`SteerVerdict` (identical string values).
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from interfaces.a2a_control import SteerVerdict

_SAT = SteerVerdict.SATISFIED
_NOT = SteerVerdict.NOT_SATISFIED
_OPEN = SteerVerdict.OPEN

# The six value planes -> their importable top-level package (SPEC §4.2). Note the
# deontic package is named `deontic`, not `loomground_deontic`.
PLANE_MODULES: dict[str, str] = {
    "deontic": "deontic",
    "norm": "loomground_norm",
    "mandate": "loomground_mandate",
    "escalation": "loomground_escalation",
    "proxy": "loomground_proxy",
    "falsifiability": "loomground_falsifiability",
}
ALL_PLANES = tuple(PLANE_MODULES)

# Test/ops override: force one or more planes "absent" without uninstalling them.
# "all" disables every plane (=> exact Phase-1 bare behaviour); else a comma list.
_DISABLE_ENV = "A2A_DISABLE_PLANES"


def _disabled(plane: str) -> bool:
    raw = os.environ.get(_DISABLE_ENV, "").strip()
    if not raw:
        return False
    if raw == "all":
        return True
    return plane in {p.strip() for p in raw.split(",") if p.strip()}


def available(plane: str) -> bool:
    """True iff the plane's package is importable AND not disabled. Cheap; uses
    ``find_spec`` (no import side-effect), keeping the bare path loomground-free."""
    if _disabled(plane):
        return False
    mod = PLANE_MODULES.get(plane)
    if mod is None:
        return False
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def availability() -> dict[str, bool]:
    """Per-plane availability snapshot (honest read of what will be real-consumed)."""
    return {p: available(p) for p in ALL_PLANES}


@dataclass
class DimensionFinding:
    """One value dimension's finding, carrying its own honest provenance (SPEC §4.3).

    ``grounded`` is True when a plane produced the verdict (``provenance`` =
    ``grounded-via-<plane>``); False when the plane was absent and the dimension
    fell back to the role advisory reading (``provenance`` = ``advisory-absent``).
    ``applicable`` is False when a present plane had no relevant input to assess —
    a not-applicable dimension, distinct from an OPEN insufficient-evidence one."""

    dimension: str
    verdict: SteerVerdict
    grounded: bool
    provenance: str
    reason: str
    applicable: bool = True
    detail: dict = field(default_factory=dict)


def _advisory(plane: str, reason: str) -> DimensionFinding:
    return DimensionFinding(
        dimension=plane,
        verdict=_OPEN,
        grounded=False,
        provenance="advisory-absent",
        reason=reason,
        applicable=True,
        detail={},
    )


def _na(plane: str, provenance: str, reason: str) -> DimensionFinding:
    # A present plane with no input for this maker: grounded, but not applicable.
    return DimensionFinding(plane, _OPEN, True, provenance, reason, applicable=False)


def _v(verdict) -> SteerVerdict:
    """Map a solver Verdict onto SteerVerdict (identical string values)."""
    return SteerVerdict(getattr(verdict, "value", verdict))


# --- the six real-consume adapters (SPEC §4.2) -----------------------------------
# Each imports its plane lazily (only when available + consumed). Generic inputs in,
# a generic SteerVerdict out — nothing here is fleet-specific (universal consumption).

_OP_TO_MODAL = {"O": "obligation", "P": "permission", "F": "prohibition"}


def assess_deontic(ctx) -> DimensionFinding:
    """Classify the O/P/F force of the compiled norms and detect that the maker's
    proposed action collides with a prohibition (same-bearer/same-action O-vs-F clash)."""
    import deontic

    policy = ctx.policy or {}
    norms = policy.get("norms", [])
    action = ctx.proposed_action
    if not action or not norms:
        return _na("deontic", "grounded-via-deontic",
                   "no proposed action or no compiled norms to check against")

    formulae = [
        deontic.formula_from_fields(
            _OP_TO_MODAL.get(n.get("operator", "P"), "permission"),
            n.get("bearer", ""), n.get("action", ""),
            condition=n.get("condition", ""), exception=n.get("exception", ""),
        )
        for n in norms
    ]
    # The maker's proposed action expressed as an intent it is committed to (O), so a
    # policy F on the same bearer/action surfaces as an O-vs-F clash.
    maker_f = deontic.formula_from_fields(
        "obligation", action.get("bearer", ""), action.get("action", ""),
        condition=action.get("condition", ""),
    )
    conflicts = deontic.detect_conflicts(formulae + [maker_f])
    collisions = [
        c for c in conflicts
        if c.get("bearer") == action.get("bearer")
        and c.get("action") == action.get("action")
        and "F" in (c.get("operator_a"), c.get("operator_b"))
    ]
    if collisions:
        return DimensionFinding(
            "deontic", _NOT, True, "grounded-via-deontic",
            f"proposed action collides with a prohibition: {collisions[0].get('formula_b')}",
            detail={"conflicts": collisions},
        )
    return DimensionFinding(
        "deontic", _SAT, True, "grounded-via-deontic",
        "no prohibition collision for the proposed action",
        detail={"n_norms": len(norms)},
    )


def assess_norm(ctx) -> DimensionFinding:
    """Turn raw policy prose into extracted O/P/F duties and check the maker's proposed
    action against them (extract_rules + formula_from_rule)."""
    import deontic
    import loomground_norm as N

    text = ctx.policy_text
    if not text:
        return _na("norm", "grounded-via-norm",
                   "no raw policy text supplied for rule extraction")

    rules = N.extract_rules(text)
    duties = [deontic.project(N.formula_from_rule(r)) for r in rules]
    action = (ctx.proposed_action or {}).get("action", "")

    def _matches(duty_action: str) -> bool:
        if not action or not duty_action:
            return False
        return action in duty_action or duty_action in action

    forb = [d for d in duties if d["operator"] == "F" and _matches(d["action"])]
    if forb:
        return DimensionFinding(
            "norm", _NOT, True, "grounded-via-norm",
            f"proposed action matches an extracted prohibition duty: {forb[0]['action']!r}",
            detail={"n_duties": len(duties)},
        )
    oblig = [d for d in duties if d["operator"] == "O" and _matches(d["action"])]
    if oblig:
        return DimensionFinding(
            "norm", _SAT, True, "grounded-via-norm",
            "proposed action fulfils an extracted obligation duty",
            detail={"n_duties": len(duties)},
        )
    return DimensionFinding(
        "norm", _OPEN, True, "grounded-via-norm",
        f"extracted {len(duties)} duties; proposed action matches none — unassessed",
        applicable=bool(action),
        detail={"n_duties": len(duties)},
    )


def assess_mandate(ctx) -> DimensionFinding:
    """Does the maker's trajectory serve the purpose it was given? (detect + fold)."""
    import loomground_mandate as M
    from loomground_solver.interop import EvidenceRef

    m = ctx.mandate
    traj = ctx.trajectory
    if not m or not traj:
        return _na("mandate", "grounded-via-mandate",
                   "no mandate or trajectory supplied")

    purposes = m.get("purposes")
    if not purposes and m.get("purpose"):
        purposes = [m["purpose"]]
    mandate_src = m.get("evidence", "mandate")

    class _Store:
        """Minimal EvidenceProvider: verifies exactly the refs declared grounded."""

        def __init__(self, known):
            self._known = set(known)

        def resolve(self, ref):
            if ref.source_id not in self._known:
                raise KeyError(ref.source_id)
            return {"source_id": ref.source_id}

        def verify(self, ref):
            return ref.source_id in self._known

    known = {mandate_src}
    steps = []
    for s in traj:
        src = s.get("evidence", mandate_src)
        if s.get("grounded", True):
            known.add(src)
        steps.append(
            M.TrajectoryStep(
                s.get("step", ""), EvidenceRef(source_id=src),
                serves=frozenset(s.get("serves", [])),
                defeats=frozenset(s.get("defeats", [])),
            )
        )
    mandate = M.Mandate(EvidenceRef(source_id=mandate_src), frozenset(purposes or []))
    divs = M.detect(mandate, steps, evidence=_Store(known))
    if divs:
        return DimensionFinding(
            "mandate", _NOT, True, "grounded-via-mandate",
            f"trajectory diverges from mandate: {sorted({d.kind for d in divs})}",
            detail={"divergences": [{"kind": d.kind, "ref": d.ref, "why": d.why} for d in divs]},
        )
    return DimensionFinding(
        "mandate", _SAT, True, "grounded-via-mandate",
        "trajectory serves the mandate purpose", detail={},
    )


def assess_escalation(ctx) -> DimensionFinding:
    """Requested autonomy vs the ceiling the factors leave (ceiling + autonomy_verdict)."""
    import loomground_escalation as E

    au = ctx.autonomy
    if not au:
        return _na("escalation", "grounded-via-escalation",
                   "no autonomy request/factors supplied")

    ladder = E.Ladder(tuple(au.get("ladder") or ("L0", "L1", "L2", "L3", "L4")))
    factors = [
        E.Factor(f.get("name", ""), ceiling=f.get("ceiling"), why=f.get("why", ""))
        for f in au.get("factors", [])
    ]
    requested = au.get("requested", "L0")
    esc = E.ceiling(factors, delegated=au.get("delegated", requested), ladder=ladder)
    verdict = _v(E.autonomy_verdict(requested, esc))
    return DimensionFinding(
        "escalation", verdict, True, "grounded-via-escalation",
        f"requested={requested} granted={esc.granted} binding={list(esc.binding)}",
        detail={"granted": esc.granted, "binding": list(esc.binding)},
    )


def assess_proxy(ctx) -> DimensionFinding:
    """Goodhart check: is a proxy metric gamed (up while its value fell)? (check_proxies)."""
    import loomground_proxy as P

    prox = ctx.proxies
    if not prox:
        return _na("proxy", "grounded-via-proxy", "no proxy readings supplied")

    move = {
        "improved": P.Movement.IMPROVED, "up": P.Movement.IMPROVED,
        "worsened": P.Movement.WORSENED, "down": P.Movement.WORSENED,
        "unchanged": P.Movement.UNCHANGED, "unmeasured": P.Movement.UNMEASURED,
    }

    def _m(v):
        return move.get(str(v).lower(), P.Movement.UNMEASURED)

    proxies, readings = [], {}
    for pr in prox:
        proxies.append(P.Proxy(pr["metric"], pr["stands_for"]))
        readings[pr["metric"]] = _m(pr.get("metric_movement", "unmeasured"))
        readings[pr["stands_for"]] = _m(pr.get("value_movement", "unmeasured"))
    subs = P.check_proxies(proxies, readings)
    kinds = {s.kind for s in subs}
    if "gamed" in kinds:
        verdict, reason = _NOT, "a proxy is gamed (metric improved while its value worsened)"
    elif kinds and kinds <= {"tracking"}:
        verdict, reason = _SAT, "proxies still track their values"
    else:
        verdict, reason = _OPEN, f"proxy status unresolved: {sorted(kinds)}"
    return DimensionFinding(
        "proxy", verdict, True, "grounded-via-proxy", reason,
        detail={"substitutions": [{"kind": s.kind, "metric": s.metric} for s in subs]},
    )


def assess_falsifiability(ctx) -> DimensionFinding:
    """Evidence-quality gate: does the maker's self-report clear the support floor?"""
    import loomground_falsifiability as F

    claims = ctx.claims
    if not claims:
        return _na("falsifiability", "grounded-via-falsifiability", "no claims supplied")

    tier = {
        "self_report": F.Falsifiability.SELF_REPORT,
        "declared_plan": F.Falsifiability.DECLARED_PLAN,
        "observed_tool_call": F.Falsifiability.OBSERVED_TOOL_CALL,
        "verified_outcome": F.Falsifiability.VERIFIED_OUTCOME,
        "span_grounded": F.Falsifiability.SPAN_GROUNDED,
        "replayable": F.Falsifiability.REPLAYABLE,
    }
    evidence = [
        tier.get(str(c.get("falsifiability", "self_report")).lower(), F.Falsifiability.SELF_REPORT)
        for c in claims
    ]
    verdict = _v(F.support_verdict(evidence, floor=F.SUPPORT_FLOOR))
    best = F.best_support(evidence)
    return DimensionFinding(
        "falsifiability", verdict, True, "grounded-via-falsifiability",
        f"evidence support {'meets' if verdict is _SAT else 'below'} the floor",
        detail={"best": best.name if best is not None else None},
    )


_ASSESSORS: dict[str, Callable[[object], DimensionFinding]] = {
    "deontic": assess_deontic,
    "norm": assess_norm,
    "mandate": assess_mandate,
    "escalation": assess_escalation,
    "proxy": assess_proxy,
    "falsifiability": assess_falsifiability,
}


def assess(plane: str, ctx) -> DimensionFinding:
    """Evaluate one dimension. Absent plane -> advisory fallback; a plane that raises
    also degrades to advisory for that dimension. NEVER raises because a plane is
    absent or misbehaves (SPEC §4.3)."""
    if not available(plane):
        return _advisory(plane, f"{plane} plane not present — advisory/role reading applies")
    assessor = _ASSESSORS.get(plane)
    if assessor is None:
        return _advisory(plane, f"no assessor for {plane!r}")
    try:
        return assessor(ctx)
    except Exception as exc:  # a plane must never crash the op
        return _advisory(
            plane,
            f"{plane} plane raised {type(exc).__name__}: {exc}; advisory reading applies",
        )
