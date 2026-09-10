"""a2a-compliance — Phase 1: bare A2A control channel + role authority.

Working, tested implementation of the SPEC's Phase-1 scope (SPEC §12.1):
- the A2A control-message contract (envelope + verbs), `grounding`/`enforcement`
  null — `envelope`, `schema`;
- role-based authority from the ctrl team-charter roster — `authority`;
- the governance-block reader (steer within the declared boundary) —
  `governance_block`;
- the maker-side cooperative-poll control-participant shim — `inbox`,
  `participant`;
- the compliance-agent send side — `channel`.

Works with ZERO loomground and ZERO RVND. The loomground value-grounding
(Phase 2) and RVND enforcement (Phase 3) are declared-but-inert optional seams
(`grounding=None`, `enforcement=None`); no `loomground_*` / `rvnd.*` import is on
this path.
"""

from interfaces.a2a_control import (
    Verb,
    SteerVerdict,
    Party,
    Authority,
    Grounding,
    PlaneFinding,
    Enforcement,
    Message,
)
from . import envelope
from . import schema
from .authority import (
    Roster,
    Authorization,
    authorize,
    COMPLIANCE_ROLES,
    MAKER_ROLES,
)
from .governance_block import GovernanceBlock, SteerDecision, SteerRuling
from .inbox import FileInbox
from .participant import ControlParticipant, DirectiveRecord
from .channel import ComplianceAgent, DispatchResult

__all__ = [
    "Verb",
    "SteerVerdict",
    "Party",
    "Authority",
    "Grounding",
    "PlaneFinding",
    "Enforcement",
    "Message",
    "envelope",
    "schema",
    "Roster",
    "Authorization",
    "authorize",
    "COMPLIANCE_ROLES",
    "MAKER_ROLES",
    "GovernanceBlock",
    "SteerDecision",
    "SteerRuling",
    "FileInbox",
    "ControlParticipant",
    "DirectiveRecord",
    "ComplianceAgent",
    "DispatchResult",
]
