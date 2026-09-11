"""a2a-compliance — value-plane consumption seam (SPEC stage, interface-only).

No logic. Defines the UNIVERSAL, OPTIONAL, per-plane interface by which a
compliance agent draws a steer/hold criterion from the loomground value graph
(SPEC §4). Every plane is behind an `available()` flag: absent/unimportable =>
flag off => advisory fallback for that dimension (SPEC §4.3). Nothing here is a
hard dependency; nothing here is fleet-specific.

Honest read (SPEC §4.2): all six value planes are REAL-CONSUME — each has an
installed, importable package with a typed API returning the common solver
Verdict. The imports are shown as guarded stubs; the real symbols are named in
the docstrings so the seam is unambiguous.
"""

from __future__ import annotations
from typing import Protocol, Optional, Iterable, Mapping
from .a2a_control import SteerVerdict, PlaneFinding, Grounding


class ValuePlane(Protocol):
    """Universal per-plane interface. A plane is consumed as a general
    capability: generic inputs in, a generic SteerVerdict out. `available()`
    gates it; when False the fleet uses the plane's advisory fallback."""

    name: str  # deontic|norm|mandate|escalation|proxy|falsifiability

    def available(self) -> bool:
        """True iff the plane's package is importable. Cheap, cached. When
        False the fleet MUST use the advisory fallback for this dimension and
        MUST NOT fabricate a grounded verdict (SPEC §4.3)."""
        ...

    def assess(self, subject: dict) -> PlaneFinding:
        """Evaluate the maker `subject` against this value plane. Returns a
        PlaneFinding carrying a SteerVerdict + plane-specific detail. Only
        called when available()."""
        ...


# --- the six planes: real-consume interfaces (SPEC §4.2) -------------------
# Each maps a generic call to the real loomground symbol. REAL-CONSUME.

class DeonticPlane(Protocol):
    """loomground-deontic (pkg `deontic`). REAL-CONSUME.
    Real: parse(text)->DeonticFormula; project(f)->{'operator':'O'|'P'|'F',...};
    formula_from_fields(...); compose([...]).conflicts; conflict_candidates([...]).
    Criterion: O/P/F force of a norm + O-vs-F clash with a maker action.
    Fallback: role reads policy prose, judges 'looks forbidden/required'."""
    def force(self, norm_text: str) -> str: ...           # -> "O"|"P"|"F"
    def clashes(self, formulae: list) -> list[dict]: ...


class NormPlane(Protocol):
    """loomground-norm (pkg `loomground_norm`). REAL-CONSUME.
    Real: extract_rules(sentence)->[RuleFacet]; formula_from_rule(r)->DeonticFormula;
    ObligationRegistry + ObligationScheduler.tick(...)->SchedulerReport.
    Criterion: prose policy -> tracked O/P/F duties; open/breached/discharged over time.
    Fallback: role hand-reads policy each time; no live obligation-state tracking."""
    def extract_duties(self, policy_text: str) -> list: ...
    def duty_state(self, maker_id: str) -> SteerVerdict: ...


class MandatePlane(Protocol):
    """loomground-mandate (pkg `loomground_mandate`). REAL-CONSUME.
    Real: detect(mandate, steps, *, evidence)->(Divergence,...)
    kinds ungrounded|defeats-purpose|out-of-mandate|unserved; fold_divergences(...).
    Criterion: does the maker's trajectory serve its given purpose? NOT_SATISFIED => hold.
    Fallback: role eyeballs report-state trajectory vs the maker's brief."""
    def divergence(self, mandate: dict, steps: Iterable[dict]) -> SteerVerdict: ...


class EscalationPlane(Protocol):
    """loomground-escalation (pkg `loomground_escalation`). REAL-CONSUME.
    Real: ceiling(factors,*,delegated,ladder)->Escalation;
    autonomy_verdict(requested,escalation)->Verdict; fold_autonomy(...).
    Criterion: requested autonomy vs granted ceiling; NOT_SATISFIED => escalate/hold.
    Fallback: role uses the charter grade ladder by hand (coarser, non-weakest-link)."""
    def autonomy_ceiling(self, requested: str, factors: Iterable[dict]) -> SteerVerdict: ...


class ProxyPlane(Protocol):
    """loomground-proxy (pkg `loomground_proxy`). REAL-CONSUME.
    Real: check_proxies(proxies, readings)->(Substitution,...)
    kinds gamed|misleading|unchecked|tracking; fold_substitutions(...).
    Criterion: Goodhart — proxy up while underlying value down => 'gamed' => hold.
    Fallback: role watches for obvious metric-gaming by inspection."""
    def alignment(self, proxies: Iterable[dict], readings: Mapping[str, str]) -> SteerVerdict: ...


class FalsifiabilityPlane(Protocol):
    """loomground-falsifiability (pkg `loomground_falsifiability`). REAL-CONSUME.
    Real: support_verdict(evidence,*,floor)->Verdict; best_support(...); fold_support(...);
    Falsifiability IntEnum SELF_REPORT..REPLAYABLE; SUPPORT_FLOOR=DECLARED_PLAN.
    Criterion: OPEN (escalate) when success rests only on self-report vs observed/replayable.
    Fallback: role applies the report-state provenance tier by hand."""
    def evidence_quality(self, claims: Iterable[dict], floor: Optional[str] = None) -> SteerVerdict: ...


# --- the fleet's derivation entry point (SPEC §4) --------------------------

class ComplianceFleet(Protocol):
    """Derives a directive's criterion. In mode (a) returns Grounding=None and
    an advisory reason (the role's judgement). In mode (b) folds the available
    planes' verdicts (OPEN-dominant weakest-link) into a Grounding. A directive
    may be PARTLY grounded — each dimension carries its own honest provenance
    (SPEC §4.3)."""

    def derive_criterion(self, maker_state: dict) -> tuple[Optional[Grounding], str]:
        """Returns (grounding_or_None, advisory_reason). grounding is None when
        no value plane is present; otherwise the folded value-graph verdict.
        NEVER raises because a plane is absent."""
        raise NotImplementedError
