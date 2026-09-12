"""Role-based authority — Axis B, the hard footing (SPEC §5.1).

Answers: may THIS compliance role issue THIS verb to THIS maker? Authority is
independent of the channel and needs neither loomground nor external enforcement. It derives
from the ctrl team-charter roster: the persistent compliance/core roles oversee
the fresh-hire maker sessions.

`halt` is authorized by role but is a RESERVED act — surfaced to the human
before dispatch in every mode (charter oversight rule: the team never decides
over the human's head).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from interfaces.a2a_control import Verb, Authority

# The ctrl team-charter roster (team-charter.md).
COMPLIANCE_ROLES = frozenset({"policy-compliance", "grounding", "verify"})
CORE_ROLES = COMPLIANCE_ROLES | frozenset({"po", "retro", "doctor"})
MAKER_ROLES = frozenset(
    {
        "backend",
        "frontend-qa",
        "plane-engineer",
        "knowledge-engineer",
        "solver-engineer",
        "docs-writer",
        "governance-analyst",
        "legal-reviewer",
        "vertical-expert",
        "maker",
    }
)

# compliance -> maker verbs that a compliance role may drive (SPEC §3.2).
_STEER_VERBS = frozenset(
    {Verb.QUERY_STATE, Verb.ISSUE_DIRECTIVE, Verb.HOLD, Verb.RESUME, Verb.HALT}
)
# halt is a reserved act in EVERY mode (SPEC §3.2, §5.1).
_RESERVED_VERBS = frozenset({Verb.HALT})


@dataclass
class Authorization:
    """The verdict of the authority model. `reserved=True` means the act is
    authorized by role but MUST be surfaced to the human before dispatch."""

    allowed: bool
    reserved: bool
    reason: str
    basis: str = "role"
    role: Optional[str] = None
    oversees: Optional[str] = None

    def to_block(self) -> Authority:
        """The `authority` envelope block for a message carrying this verdict."""
        return Authority(
            basis=self.basis,
            role=self.role,
            oversees=self.oversees,
            reserved=self.reserved,
        )


@dataclass
class Roster:
    """Who oversees whom. A compliance role oversees a set of maker ids; the
    default (`oversees_all`) grants oversight of every maker, matching the
    core-hires-makers model. Narrow it to test out-of-oversight denial."""

    oversight: dict[str, set[str]] = field(default_factory=dict)
    oversees_all: bool = True

    def oversees(self, role: str, maker_id: str) -> bool:
        if role not in COMPLIANCE_ROLES:
            return False
        if maker_id in self.oversight.get(role, set()):
            return True
        return self.oversees_all and role not in self.oversight

    def assign(self, role: str, maker_id: str) -> None:
        self.oversight.setdefault(role, set()).add(maker_id)


def authorize(
    *, from_role: str, verb: Verb, maker_id: str, roster: Optional[Roster] = None
) -> Authorization:
    """Resolve authority for a compliance -> maker control verb (SPEC §5.1)."""
    roster = roster or Roster()

    if verb not in _STEER_VERBS:
        return Authorization(
            allowed=False,
            reserved=False,
            reason=(
                f"{verb.value!r} is a maker->compliance verb; it is not driven "
                "by the compliance authority model"
            ),
            role=from_role,
            oversees=maker_id,
        )

    if from_role not in COMPLIANCE_ROLES:
        return Authorization(
            allowed=False,
            reserved=False,
            reason=(
                f"role {from_role!r} is not a compliance role "
                f"{sorted(COMPLIANCE_ROLES)}; only a compliance role may steer a maker"
            ),
            role=from_role,
            oversees=maker_id,
        )

    if not roster.oversees(from_role, maker_id):
        return Authorization(
            allowed=False,
            reserved=False,
            reason=f"role {from_role!r} does not oversee maker {maker_id!r}",
            role=from_role,
            oversees=maker_id,
        )

    reserved = verb in _RESERVED_VERBS
    reason = (
        f"{from_role} may {verb.value} {maker_id} by role authority"
        + ("; RESERVED — surface to human before dispatch" if reserved else "")
    )
    return Authorization(
        allowed=True,
        reserved=reserved,
        reason=reason,
        role=from_role,
        oversees=maker_id,
    )
