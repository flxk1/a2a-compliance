"""Governance-block reader — steer within the declared boundary (SPEC §7).

Consumes a maker's declared `skill-governance-block` (the vendor-neutral spec at
`skill-governance-block/`) and bounds A2A steering by it. This module CONSUMES
the block; it does not redefine it.

The plan-time reader rule (governance-block SPEC §7): a compliance agent may
steer within `actions[]`, MUST route `reserved[]` kinds to the human, MUST NEVER
direct a maker into a `prohibited[]` kind, and carries `obligations[]` as
release accept-criteria. Fail-closed: a directive naming a kind the block does
not declare in `actions[]` is OUTSIDE the declared boundary and is refused.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class SteerDecision(str, Enum):
    STEER = "steer"              # kind ∈ actions[] — within boundary
    ROUTE_HUMAN = "route-human"  # kind ∈ reserved[] — surface to the human
    REFUSE = "refuse"            # kind ∈ prohibited[] OR undeclared — outside boundary


@dataclass
class SteerRuling:
    decision: SteerDecision
    kind: str
    reason: str
    reserved_by: Optional[object] = None  # the reservation target, when ROUTE_HUMAN


@dataclass
class GovernanceBlock:
    """A parsed maker governance block. Only the fields A2A steering needs are
    interpreted; unknown fields are ignored (forward-compatibility)."""

    grade: Optional[str] = None
    action_kinds: set[str] = field(default_factory=set)
    reserved: dict[str, object] = field(default_factory=dict)  # kind -> target
    prohibited: set[str] = field(default_factory=set)
    obligations: list[str] = field(default_factory=list)
    budget: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, block: dict) -> "GovernanceBlock":
        actions = block.get("actions", []) or []
        reserved_list = block.get("reserved", []) or []
        return cls(
            grade=block.get("grade"),
            action_kinds={a["kind"] for a in actions if "kind" in a},
            reserved={r["kind"]: r.get("by") for r in reserved_list if "kind" in r},
            prohibited=set(block.get("prohibited", []) or []),
            obligations=list(block.get("obligations", []) or []),
            budget=dict(block.get("budget", {}) or {}),
        )

    @classmethod
    def from_manifest(cls, path: str | Path) -> "GovernanceBlock":
        """Parse the `governance:` block out of a SKILL.md YAML frontmatter."""
        import yaml  # PyYAML; guarded so a missing dep is an honest, clear error

        text = Path(path).read_text(encoding="utf-8")
        if not text.startswith("---"):
            raise ValueError(f"{path}: no YAML frontmatter")
        _, _, rest = text.partition("---\n")
        front, sep, _ = rest.partition("\n---")
        if not sep:
            raise ValueError(f"{path}: unterminated YAML frontmatter")
        data = yaml.safe_load(front) or {}
        block = data.get("governance")
        if block is None:
            raise ValueError(f"{path}: manifest has no `governance` block")
        return cls.from_dict(block)

    # --- the steering bound (SPEC §7) -------------------------------------

    def rule(self, kind: str) -> SteerRuling:
        """Decide whether A2A may steer a maker toward an action `kind`.

        prohibited wins over everything (fail-closed); then reserved; then
        actions[]; an undeclared kind is refused as outside the boundary."""
        if kind in self.prohibited:
            return SteerRuling(
                SteerDecision.REFUSE,
                kind,
                f"{kind!r} is prohibited by the maker's governance block — "
                "never direct a maker into a prohibited kind",
            )
        if kind in self.reserved:
            return SteerRuling(
                SteerDecision.ROUTE_HUMAN,
                kind,
                f"{kind!r} is reserved to {self.reserved[kind]!r} — route to the human",
                reserved_by=self.reserved[kind],
            )
        if kind in self.action_kinds:
            return SteerRuling(
                SteerDecision.STEER,
                kind,
                f"{kind!r} is within the maker's declared actions[] — steer permitted",
            )
        return SteerRuling(
            SteerDecision.REFUSE,
            kind,
            f"{kind!r} is not declared in the maker's actions[] — outside the "
            "declared boundary; the block is the outer envelope A2A steers inside",
        )

    def may_steer(self, kind: str) -> bool:
        return self.rule(kind).decision is SteerDecision.STEER
