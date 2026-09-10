"""a2a-compliance interfaces — the SEAM (envelope types + Protocols).

These are the contract. Concrete Phase-1 bodies live in the `a2a_compliance`
package and satisfy the Protocols declared here. `grounding` (Phase 2) and
`enforcement` (Phase 3) stay declared-but-inert in Phase 1.
"""

from .a2a_control import (
    Verb,
    SteerVerdict,
    Party,
    Authority,
    Grounding,
    PlaneFinding,
    Enforcement,
    Message,
    MakerParticipant,
    ComplianceChannel,
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
    "MakerParticipant",
    "ComplianceChannel",
]
