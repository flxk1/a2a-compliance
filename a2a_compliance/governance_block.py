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
from typing import Callable, Optional


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

    # --- pinned governance block (quick win 9) ----------------------------

    def to_dict(self) -> dict:
        """A deterministic, JSON-safe view of the declared boundary this
        block actually enforces -- the input `digest()` hashes. Sets/dict
        become sorted lists/mappings so two `GovernanceBlock`s built from the
        same logical content always hash identically, regardless of the
        original YAML's key order."""
        return {
            "grade": self.grade,
            "actions": sorted(self.action_kinds),
            "reserved": {k: self.reserved[k] for k in sorted(self.reserved)},
            "prohibited": sorted(self.prohibited),
            "obligations": list(self.obligations),
            "budget": dict(self.budget),
        }

    def digest(self) -> str:
        """RFC 8785 canonical digest of `to_dict()` (quick win 9: pin the
        governance block). Lazily imports `wire.canonical` -- `wire/__init__`
        does not import `governance_block`, so this import is safe eagerly
        too, but the plan calls for a lazy import here to keep this module's
        own import graph independent of `wire`'s until a caller actually
        needs a digest."""
        from .wire import canonical

        return canonical.digest_hex(self.to_dict())


@dataclass(frozen=True)
class SignedGovernanceBlock:
    """A `GovernanceBlock` plus a policy author's signature over its pinned
    digest (quick win 9). Deliberately NOT a JSON-schema wire type (no
    envelope fields, no `wire.verify` entry) -- a lightweight signed-digest
    object that `admission.admit()` checks against a `TrustStore`-resolved
    policy-author identity, reusing `wire.signing`'s DSSE construction and
    `wire.canonical`'s digest rather than growing a second signature format.
    Built only via `sign_governance_block` below -- never construct one by
    hand for anything but a test double, exactly like every other signed
    wire object in this package."""

    block: GovernanceBlock
    digest: str
    signer_key_id: str
    signer_identity: str
    signature: str

    def subject(self) -> dict:
        """The exact dict `sign_governance_block` signed and
        `admission._governance_block_findings` re-verifies against -- no
        `signature`/`subject_digest` field of its own, so
        `wire.canonical.subject()`'s usual signature-stripping is a no-op
        here and can never diverge between signing and verifying."""
        return {
            "governance_block_digest": self.digest,
            "signer_key_id": self.signer_key_id,
            "signer_identity": self.signer_identity,
        }


def sign_governance_block(
    block: GovernanceBlock, *, key_id: str, identity: str, sign: Callable[[dict], str],
) -> SignedGovernanceBlock:
    """Sign `block.digest()` as the policy author `identity`/`key_id`.
    `sign` has the exact `Callable[[dict], str]` shape as `wire.admission.
    Issuer.sign` (a host typically passes `issuer.sign` directly) -- this
    module never imports `wire.admission.Issuer` itself, to keep this file's
    import graph independent of `admission` (which imports THIS module)."""
    digest = block.digest()
    subject = {"governance_block_digest": digest, "signer_key_id": key_id, "signer_identity": identity}
    signature = sign(subject)
    return SignedGovernanceBlock(
        block=block, digest=digest, signer_key_id=key_id, signer_identity=identity, signature=signature,
    )
