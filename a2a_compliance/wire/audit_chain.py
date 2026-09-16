"""E4 -- run audit chain (plan: 'loomground-audit-chain' -- "Append-only
receipt linkage"; "Removal, reorder or mutation is detected").

`wire/chain.py:verify_chain` links a UNIFORM sequence of one `obj_type` via
its own `prev_digest` field. A run mixes types that this slice must not
retrofit `prev_digest` onto: `ExecutionPermit` and `Reconciliation` are
already-published schemas (E0/E2) with `unevaluatedProperties: false` and no
`prev_digest` property -- adding one would change an already-published
schema's shape, which this slice must not do (see `wire/reconciliation.py`'s
docstring for the same constraint on `Reconciliation.state`). `StageReceipt`
and `ToolReceipt` already support `prev_digest` (E1/E3) and are still linked
that way here, via `chain.verify_chain`.

`audit_chain_verify` links the REST of the run by content-addressed digest
reference instead: `OversightCertificate.permit_digest`/`reconciliation_digest`/
`tool_receipt_digests` bind it to the exact `subject_digest` of the permit,
the reconciliation and each tool receipt, IN ORDER. Any removal, reorder or
mutation of any of those objects changes some digest this function
recomputes and compares -- mutation is caught by that object's own `verify()`
(subject_digest recheck), removal/reorder of a tool receipt is caught by the
list-equality check on `tool_receipt_digests`, and a swapped/replayed permit
or reconciliation is caught by the scalar digest-reference check. Pure
verification; produces nothing, dispatches nothing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

from . import canonical
from .chain import ChainVerificationResult, verify_chain
from .trust import RevocationStore, TrustStore
from .verification import verify


def audit_chain_verify(
    *,
    permit: dict,
    tool_receipts: Iterable[dict],
    reconciliation: dict,
    certificate: dict,
    stage_receipts: Iterable[dict] = (),
    trust_store: TrustStore,
    revocation_store: Optional[RevocationStore] = None,
    now: Optional[datetime] = None,
) -> ChainVerificationResult:
    """Verify one full run's assurance chain: every object individually
    E1-verifies, the `StageReceipt`/`ToolReceipt` prev_digest sub-chains (if
    more than one of either) link correctly, and the `OversightCertificate`'s
    digest-reference fields match the actual permit/reconciliation/tool-receipt
    set exactly, in order. Fail-closed: any single failure rejects the whole
    chain."""
    errors: list = []
    receipts = list(tool_receipts)
    stages = list(stage_receipts)

    if stages:
        result = verify_chain(
            stages, "StageReceipt",
            trust_store=trust_store, revocation_store=revocation_store, now=now,
        )
        if not result.ok:
            errors.extend(f"stage-receipt chain: {e}" for e in result.errors)

    if receipts:
        result = verify_chain(
            receipts, "ToolReceipt",
            trust_store=trust_store, revocation_store=revocation_store, now=now,
        )
        if not result.ok:
            errors.extend(f"tool-receipt chain: {e}" for e in result.errors)
    else:
        errors.append("tool-receipt chain: no tool receipts to verify")

    for label, obj, obj_type in (
        ("permit", permit, "ExecutionPermit"),
        ("reconciliation", reconciliation, "Reconciliation"),
        ("certificate", certificate, "OversightCertificate"),
    ):
        if not isinstance(obj, dict):
            errors.append(f"{label}: object is not a JSON object")
            continue
        result = verify(obj, obj_type, trust_store=trust_store, revocation_store=revocation_store, now=now)
        if not result.ok:
            errors.extend(f"{label}: {e}" for e in result.errors)

    if not errors:
        expected_permit_digest = canonical.subject_digest(permit)
        expected_reconciliation_digest = canonical.subject_digest(reconciliation)
        expected_receipt_digests = [canonical.subject_digest(r) for r in receipts]

        if certificate.get("permit_digest") != expected_permit_digest:
            errors.append("certificate: permit_digest does not match the actual permit")
        if certificate.get("reconciliation_digest") != expected_reconciliation_digest:
            errors.append("certificate: reconciliation_digest does not match the actual reconciliation")
        if certificate.get("tool_receipt_digests") != expected_receipt_digests:
            errors.append(
                "certificate: tool_receipt_digests does not match the actual tool-receipt "
                "set/order -- removal, reorder or substitution detected"
            )

    if errors:
        return ChainVerificationResult(False, tuple(errors))
    return ChainVerificationResult(True, ())
