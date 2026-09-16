"""E1 receipt-chain linkage: `verify_chain` checks an ordered sequence of
wire objects links correctly via the OPTIONAL envelope `prev_digest` field
(the RFC 8785 `subject_digest` of the immediately prior object in the
chain). Pure orchestration over `wire.verification.verify` and
`wire.canonical.subject_digest`; no new crypto or schema logic of its own.

Design decision (field vs. hash-chain): `prev_digest` was chosen over a
running/rolling hash-chain digest because it lets any single link be
verified in isolation against its one named predecessor -- matching how
`subject_digest` already works for one object -- and needs no extra
accumulator state threaded through `wire.verification.verify`. A rolling hash
(each digest folding in all priors) would detect the same tamper classes
but cannot say *which* link broke without replaying the whole prefix; a
named-predecessor field can. `loomground-audit-chain` (follow-on, out of
this slice) may still choose to build an append-only rolling hash-chain on
top of `prev_digest`-linked receipts; the two are compatible.

Detects removal, reorder, mutation and a missing/broken link: each of those
either changes an object's own `subject_digest` (caught by that object's own
`verify`) or breaks the `prev_digest` == `subject_digest(predecessor)`
equality checked here -- reordering and removal both leave some
`prev_digest` pointing at a digest that is no longer the immediate
predecessor's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from . import canonical
from .trust import RevocationStore, TrustStore
from .verification import NonceStore, verify


@dataclass(frozen=True)
class ChainVerificationResult:
    ok: bool
    errors: tuple[str, ...] = field(default=())


def verify_chain(
    receipts: list,
    obj_type: str,
    *,
    nonce_store: Optional[NonceStore] = None,
    trust_store: Optional[TrustStore] = None,
    revocation_store: Optional[RevocationStore] = None,
    now: Optional[datetime] = None,
    genesis_prev_digest: Optional[str] = None,
) -> ChainVerificationResult:
    """Verify each of `receipts` (all the same `obj_type`, in the given
    order) and that `receipts[i]["prev_digest"] ==
    subject_digest(receipts[i-1])` for every `i > 0`.

    `genesis_prev_digest`, if given, anchors `receipts[0]["prev_digest"]` to
    an external prior chain segment; if omitted (the default), `receipts[0]`
    must carry no `prev_digest` at all (a true genesis link).

    Fail-closed: an empty chain, any single object's own verification
    failure, or any link mismatch rejects the WHOLE chain -- never only the
    one bad element.
    """
    if not receipts:
        return ChainVerificationResult(False, ("empty chain",))

    errors: list[str] = []
    prior_digest = genesis_prev_digest
    for i, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            errors.append(f"chain[{i}]: object is not a JSON object")
            prior_digest = None
            continue

        result = verify(
            receipt, obj_type,
            nonce_store=nonce_store, trust_store=trust_store,
            revocation_store=revocation_store, now=now,
        )
        if not result.ok:
            errors.append(f"chain[{i}]: " + "; ".join(result.errors))

        claimed_prev = receipt.get("prev_digest")
        if claimed_prev != prior_digest:
            if i == 0:
                errors.append(
                    f"chain[0]: prev_digest does not match the chain anchor "
                    f"(expected {prior_digest!r}, found {claimed_prev!r})"
                )
            else:
                errors.append(
                    f"chain[{i}]: missing or broken link (prev_digest does "
                    "not match the immediately prior object's digest)"
                )

        try:
            prior_digest = canonical.subject_digest(receipt)
        except (TypeError, ValueError):
            # Uncanonicalisable -- already reported via `result.errors`
            # above; nothing downstream can validly link to it.
            prior_digest = None

    if errors:
        return ChainVerificationResult(False, tuple(errors))
    return ChainVerificationResult(True, ())
