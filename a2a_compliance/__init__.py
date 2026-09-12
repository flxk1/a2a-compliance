"""a2a-compliance — bare A2A control channel, role authority, and loomground value grounding.

Implements the SPEC's Phase 1 and Phase 2 scope (SPEC §12.1-2):
- the A2A control-message contract (envelope + verbs) — `envelope`, `schema`;
- role-based authority from the ctrl team-charter roster — `authority`;
- the governance-block reader (steer within the declared boundary) —
  `governance_block`;
- the maker-side cooperative-poll control-participant shim — `inbox`,
  `participant`;
- the compliance-agent send side — `channel`;
- per-plane loomground value consumption and the grounded steer/hold/escalate
  decision — `planes`, `grounding`.

Works with zero Loomground and zero external enforcement: each Loomground plane degrades to the
bare advisory/role reading when absent, and no `loomground_*` import happens
until a present plane is actually consumed. External enforcement (Phase 3) is a
declared, flag-gated seam (`enforcement=None` until an adapter lands); no host
enforcer is imported on this path.
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
from . import planes
from .planes import ALL_PLANES, DimensionFinding, available, availability
from . import grounding
from .grounding import (
    GroundingContext,
    GroundingResult,
    accept_compiled_policy,
    ground,
    ACTION_NO_STEER,
    ACTION_STEER,
    ACTION_HOLD,
    ACTION_ROUTE_HUMAN,
)
from .team import (
    TeamProfile,
    CapabilityKind,
    Capability,
    ComplianceRole,
    RoleManifest,
    role_manifests,
    COMPLIANCE_ROLES as TEAM_ROLES,
    LOOMGROUND_REPOSITORIES,
    CapabilityInventory,
    ControlRequest,
    RoleStep,
    ControlPlan,
    ComplianceTeam,
)

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
    "planes",
    "ALL_PLANES",
    "DimensionFinding",
    "available",
    "availability",
    "grounding",
    "GroundingContext",
    "GroundingResult",
    "accept_compiled_policy",
    "ground",
    "ACTION_NO_STEER",
    "ACTION_STEER",
    "ACTION_HOLD",
    "ACTION_ROUTE_HUMAN",
    "TeamProfile",
    "CapabilityKind",
    "Capability",
    "ComplianceRole",
    "RoleManifest",
    "role_manifests",
    "TEAM_ROLES",
    "LOOMGROUND_REPOSITORIES",
    "CapabilityInventory",
    "ControlRequest",
    "RoleStep",
    "ControlPlan",
    "ComplianceTeam",
]
