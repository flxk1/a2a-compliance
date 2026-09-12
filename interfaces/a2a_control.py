"""a2a-compliance — control-channel interface (SPEC stage, interface-only).

No logic. Type/signature stubs for the A2A control message contract (SPEC §3),
the maker control-participant contract (SPEC §9), and the authority model
(SPEC §5). Every body raises NotImplementedError; this file defines the SEAM,
not the implementation.

Three modes (SPEC §2): (a) bare = role advisory; (b) +loomground = grounded
criteria; (c) +external enforcement = enforced verdict + chain. `grounding` and
`enforcement` are additive envelope planes — None in the modes that lack them.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, Optional


# --- verbs -----------------------------------------------------------------

class Verb(str, Enum):
    # compliance -> maker
    QUERY_STATE = "query-state"
    ISSUE_DIRECTIVE = "issue-directive"
    HOLD = "hold"
    RESUME = "resume"
    HALT = "halt"
    # maker -> compliance
    REPORT_STATE = "report-state"
    ACK = "ack"
    ESCALATE = "escalate"


# --- solver verdict (mirrors loomground_solver; NOT imported here) ---------

class SteerVerdict(str, Enum):
    """The common solver Verdict every value plane returns (SPEC §4.1).
    SATISFIED -> no steer; NOT_SATISFIED -> steer/hold; OPEN -> escalate."""
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"
    OPEN = "open"


# --- envelope planes -------------------------------------------------------

@dataclass
class Party:
    actor: str
    role: str  # a charter role (policy-compliance/grounding/verify) or "maker"


@dataclass
class Authority:
    """Axis B (SPEC §5). basis='role' is the hard footing; external enforcement
    sharpens it via Enforcement, it does not replace this."""
    basis: str = "role"
    role: Optional[str] = None
    oversees: Optional[str] = None
    reserved: bool = False  # True => surfaced to the human before dispatch


@dataclass
class Grounding:
    """Optional (SPEC §4). Populated only when a loomground value plane is
    present; None otherwise (advisory fallback). Per-plane verdicts fold to a
    single OPEN-dominant weakest-link verdict."""
    verdict: SteerVerdict
    planes: list["PlaneFinding"] = field(default_factory=list)
    criterion_ref: Optional[str] = None


@dataclass
class PlaneFinding:
    plane: str  # deontic|norm|mandate|escalation|proxy|falsifiability
    verdict: SteerVerdict
    detail: dict = field(default_factory=dict)


@dataclass
class Enforcement:
    """Optional (SPEC §6). None unless external enforcement is present.
    advisory=True => preview only (chain NOT written); advisory=False =>
    enforced (chain written)."""
    engine: str = "external"
    verdict: str = "permit"        # permit|hold|deny
    gate_verdict: Optional[str] = None  # GO|CONDITIONAL|NO-GO
    audit_id: Optional[str] = None
    advisory: bool = True


@dataclass
class Message:
    """One A2A control message (SPEC §3.1). grounding/enforcement are additive:
    None is a valid state, never a failure."""
    id: str
    ts: str
    from_: Party
    to: Party
    verb: Verb
    body: dict
    authority: Authority
    protocol: str = "a2a-compliance/0.1"
    correlates: Optional[str] = None
    grounding: Optional[Grounding] = None      # None in mode (a)
    enforcement: Optional[Enforcement] = None  # None in modes (a)/(b)


# --- maker control-participant contract (SPEC §9) --------------------------

class MakerParticipant(Protocol):
    """What a maker must expose to be A2A-controllable. STUB today: fresh-hire
    subagents do NOT expose this on a live inbound channel — see SPEC §9/§11.
    The Phase-1 shim (cooperative poll / spawn-time compile) implements this."""

    def accept_directive(self, msg: Message) -> Message:
        """Honour an issue-directive/hold/resume WITHIN the declared governance
        boundary (SPEC §7). Returns an `ack` message. A principled refusal is
        ack{accepted:false} which routes to escalate."""
        raise NotImplementedError

    def report_state(self, query: Message) -> Message:
        """Answer a query-state. Returns a `report-state` message stamped
        provenance='self-report' — NEVER promoted to witnessed/observed."""
        raise NotImplementedError

    def halt(self, msg: Message) -> Message:
        """Stop on a halt directive. In bare mode this is a COOPERATIVE stop at
        the next checkpoint, not a forced kill (SPEC §9)."""
        raise NotImplementedError


# --- compliance-agent send side (SPEC §3.2, §5) ---------------------------

class ComplianceChannel(Protocol):
    """The compliance agent's send side. Authority is resolved role-first
    (SPEC §5.1); external enforcement enrichment, if present, is applied by the
    adapter before dispatch (SPEC §6). None of these methods fail because an
    enrichment plane is absent."""

    def query_state(self, maker: str, include: list[str]) -> Message: ...
    def issue_directive(self, maker: str, instruction: str, kind: str,
                        grounding: Optional[Grounding] = None) -> Message: ...
    def hold(self, maker: str, scope: str,
             grounding: Optional[Grounding] = None,
             conditions: Optional[list[str]] = None) -> Message: ...
    def resume(self, maker: str, hold_ref: str) -> Message: ...
    def halt(self, maker: str, grounding: Optional[Grounding] = None) -> Message:
        """Reserved act: MUST be surfaced to the human before dispatch in every
        mode (SPEC §3.2, §5.1)."""
        ...
