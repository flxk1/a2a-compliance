# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Coordinate grounding for `evidence-grounder`'s coordinate tools.

`evidence-grounder` declares three coordinate tools (`versum_coords`,
`versum_cell`, `nd_resolve` -- see `roles/evidence-grounder.json` and
`team.py`'s `COMPLIANCE_ROLES`): resolve a maker's proposed 5D+nD coordinate,
the entries anchored at one nD cell, and a coordinate reference into its
canonical form + digest.

Grounding decision (contract): only a `confirmed` coordinate grounds a
finding. A `candidate` coordinate is unconfirmed and must never ground --
this repo has no `vetted` tier, so `confirmed` is the only grounding tier.

Compliance receipt (contract, additive): when grounding is used, the receipt
carries a resolved 5D+nD reference -- `{canonical_reference, digest}` --
obtained from the `5d-nd` library's `resolve`/`digest`/`normalize_reference`
seam. `a2a-compliance` does not (and per its own stdlib-only invariant, may
not) hard-depend on `5d-nd`; `5d-nd` is itself only optionally available
(the `find_spec` probe below never imports it), so this module accepts an
injected resolver callable and falls back to that optional import. Honest
degrade: when no resolver is available (5d-nd absent and none injected), the
reference is recorded `unresolved` with a reason -- never a fabricated
digest.

Determinism: `CoordinateGroundingReceipt.to_dict()` carries no wall-clock
field, and `digest()` hashes it through `wire.canonical` (RFC 8785 JCS-style
canonical bytes), so two receipts built from the same logical input always
serialize and digest identically, independent of Python dict insertion
order.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from typing import Any, Callable, Optional

# --- verification tiers -----------------------------------------------------

CANDIDATE = "candidate"
CONFIRMED = "confirmed"

# This repo has no `vetted` tier (contract: "'vetted' only if the repo
# already has that tier" -- it does not). Only `confirmed` grounds.
GROUNDING_TIERS = frozenset({CONFIRMED})

_ND_MODULE = "five_d_nd"  # the `5d-nd` distribution's import package name


def nd_available() -> bool:
    """Cheap probe (no import side-effect) for the optional `5d-nd` library,
    mirroring `planes.available()`'s `find_spec` pattern."""
    try:
        return importlib.util.find_spec(_ND_MODULE) is not None
    except (ImportError, ValueError):
        return False


@dataclass(frozen=True)
class Coordinate:
    """One coordinate `evidence-grounder`'s tools resolved -- a 5D+nD
    grounding reference (the `five_d_nd` reference shape: `{"dimensions":
    [...], "anchor": <span-reference>}`) plus its verification tier."""

    reference: dict
    verification: str

    @property
    def grounds(self) -> bool:
        """True iff this coordinate's verification tier is a grounding tier.
        A `candidate` coordinate is unconfirmed and never grounds."""
        return self.verification in GROUNDING_TIERS


# ref -> {"canonical_reference": str, "digest": {"sha256": <hex>}}
ResolverFn = Callable[[dict], dict]


def default_resolver() -> Optional[ResolverFn]:
    """Build a resolver from the optional `5d-nd` library, when installed.

    Uses `5d-nd`'s own `normalize_reference` + `digest` -- the reference-only
    canonical form and content digest, stdlib-only inside `five_d_nd` itself
    for these two functions (`five_d_nd.resolve` proper additionally needs a
    real `versum` store this repo does not carry; a caller that has one may
    inject its own resolver built on `five_d_nd.resolve` instead of this
    default). Returns `None` when `5d-nd` is not installed -- never raises."""
    if not nd_available():
        return None
    import five_d_nd as _nd  # optional; only reached when nd_available()

    def _resolve(ref: dict) -> dict:
        anchor = ref.get("anchor") if isinstance(ref, dict) else None
        if not isinstance(anchor, str) or not anchor:
            raise ValueError("coordinate reference has no string anchor")
        canonical_reference = _nd.normalize_reference(anchor)
        return {"canonical_reference": canonical_reference, "digest": _nd.digest(ref)}

    return _resolve


@dataclass(frozen=True)
class GroundingReference:
    """The additive compliance-receipt field: the resolved 5D+nD reference,
    or an honest `unresolved`/`not-grounded` marker. Never a fabricated
    digest."""

    status: str  # "resolved" | "unresolved" | "not-grounded"
    canonical_reference: Optional[str] = None
    digest: Optional[dict] = None
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"status": self.status}
        if self.canonical_reference is not None:
            d["canonical_reference"] = self.canonical_reference
        if self.digest is not None:
            d["digest"] = dict(sorted(self.digest.items()))
        if self.reason is not None:
            d["reason"] = self.reason
        return d


def resolve_grounding_reference(
    coordinate: Coordinate, *, resolver: Optional[ResolverFn] = None,
) -> GroundingReference:
    """Derive the additive grounding-reference receipt field for one
    coordinate.

    * a `candidate` coordinate never grounds: `status="not-grounded"`, no
      digest -- it is unconfirmed and must not ground a finding.
    * a `confirmed` coordinate grounds. If a resolver is available (the
      `resolver` argument, or else the optional `5d-nd` library via
      `default_resolver()`), its output is carried as `{canonical_reference,
      digest}`. If no resolver is available -- `5d-nd` absent and none
      injected -- the reference is honestly `unresolved` with a reason;
      never a fabricated digest. A resolver that raises degrades the same
      way (fail-closed, never crashes the caller).
    """
    if not coordinate.grounds:
        return GroundingReference(
            status="not-grounded",
            reason=f"verification tier {coordinate.verification!r} is unconfirmed and does not ground",
        )

    active_resolver = resolver if resolver is not None else default_resolver()
    if active_resolver is None:
        return GroundingReference(status="unresolved", reason="5d-nd resolver unavailable")

    try:
        result = active_resolver(coordinate.reference)
    except Exception as exc:  # honest-degrade: never fabricate, never propagate
        return GroundingReference(status="unresolved", reason=f"5d-nd resolve failed: {exc}")

    canonical_reference = result.get("canonical_reference") if isinstance(result, dict) else None
    digest = result.get("digest") if isinstance(result, dict) else None
    if not canonical_reference or not isinstance(digest, dict) or not digest:
        return GroundingReference(status="unresolved", reason="5d-nd resolver returned an incomplete result")
    return GroundingReference(status="resolved", canonical_reference=canonical_reference, digest=digest)


@dataclass(frozen=True)
class CoordinateGroundingReceipt:
    """The compliance receipt for one coordinate grounding decision made
    through `evidence-grounder`'s `versum_coords`/`versum_cell`/`nd_resolve`
    tools. Deterministic: `to_dict()` carries no wall-clock field, and
    `digest()` hashes the RFC 8785 canonical bytes of `to_dict()`."""

    maker_id: str
    coordinate_id: str
    verification: str
    grounded: bool
    grounding_reference: GroundingReference

    def to_dict(self) -> dict:
        return {
            "maker_id": self.maker_id,
            "coordinate_id": self.coordinate_id,
            "verification": self.verification,
            "grounded": self.grounded,
            "grounding_reference": self.grounding_reference.to_dict(),
        }

    def digest(self) -> str:
        from .wire import canonical

        return canonical.digest_hex(self.to_dict())


def build_receipt(
    maker_id: str, coordinate_id: str, coordinate: Coordinate, *, resolver: Optional[ResolverFn] = None,
) -> CoordinateGroundingReceipt:
    """Build the deterministic `CoordinateGroundingReceipt` for `coordinate`.
    Never raises: an unconfirmed coordinate degrades to `not-grounded`; a
    missing/failing resolver degrades to `unresolved` with a reason."""
    grounding_reference = resolve_grounding_reference(coordinate, resolver=resolver)
    return CoordinateGroundingReceipt(
        maker_id=maker_id,
        coordinate_id=coordinate_id,
        verification=coordinate.verification,
        grounded=coordinate.grounds,
        grounding_reference=grounding_reference,
    )
