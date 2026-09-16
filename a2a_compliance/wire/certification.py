"""E4 -- certification (plan: 'oversight-certificate' -- "Postflight
assurance"; E4 exit: "a successful tool exit alone cannot certify; only
matching effects and discharged blocking obligations can").

`certify` is the ONLY function in this package that produces a signed
`OversightCertificate`. It never trusts a summary field from an earlier
step -- it independently re-verifies the permit, every `ToolReceipt` and the
`Reconciliation` through E1 `wire.verification.verify`, and independently
re-checks every blocking obligation against fresh `ObligationDischargeReceipt`
evidence (never a caller-asserted list, see `wire/obligations.py`) and every
mandatory source's freshness, before it will sign anything. All of the
following must hold, or no certificate is produced:

1. the permit E1-verifies and was issued at an enforcement grade
   (mediated/platform) -- an unadmitted or drifted-since-admission run
   cannot certify (never retroactively admits, same rule as `wire/reconciliation.py`);
2. every `tool_receipts` entry E1-verifies and binds this permit's
   `action_digest` -- at least one is required; a run with zero receipts has
   no dispatch evidence and cannot certify;
3. the `reconciliation` E1-verifies, binds this `action_digest`, and is
   itself `certified=True` with empty `residuals`/`invalid_receipts` -- a
   successful `ToolReceipt` whose observed effects were mismatched fails
   here even though step 2 alone would have passed;
4. every id in `blocking_obligations` has a verified `ObligationDischargeReceipt`
   in `discharge_receipts` bound to this `action_digest` (see
   `wire/obligations.py` -- a fabricated, unsigned or wrong-digest receipt
   never counts, it simply fails to verify and is ignored);
5. every id in `mandatory_sources` is fresh as of the reference time,
   per the injected `FreshnessPort` -- a stale mandatory source, or a
   mandatory source with no freshness port supplied at all, blocks
   certification;
6. role separation: the certifying `signer`'s identity/key must differ from
   the permit issuer, the `Reconciliation`'s own signer (the reconciler --
   the most load-bearing separation of the set, since step 3 trusts the
   reconciliation's signed `certified` flag rather than re-deriving it from
   `ObservedEffects`: one principal signing both objects could author a
   clean reconciliation and then certify it itself), every tool-receipt
   recorder/executor, and the approver (if supplied) -- an identity serving
   an incompatible role in this run cannot also be its assurance-signer
   (plan: 'Fixed trust boundary').

Fixed trust boundary: this module never dispatches, executes, or fabricates
an obligation discharge or a freshness verdict of its own -- both arrive only
via injected ports/evidence a host supplies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional, Protocol

from . import canonical
from .admission import Issuer
from .trust import RevocationStore, TrustStore
from .verification import verify

DEFAULT_CERTIFICATE_TTL = timedelta(days=365)


class FreshnessPort(Protocol):
    """Injected, host-owned port standing in for the real `norm-freshness`
    repository (plan: 'norm-freshness'). Deployment/host judgment, never
    read from any wire object's own payload."""

    def is_fresh(self, source_id: str, *, at: datetime) -> bool: ...


class InMemoryFreshness:
    """TEST-ONLY in-memory FreshnessPort. Not durable; never use in a host.
    Every source is fresh by default; `mark_stale` flips one."""

    def __init__(self) -> None:
        self._stale: set = set()

    def mark_stale(self, source_id: str) -> None:
        self._stale.add(source_id)

    def is_fresh(self, source_id: str, *, at: datetime) -> bool:
        return source_id not in self._stale


@dataclass(frozen=True)
class CertificationResult:
    ok: bool
    certificate: Optional[dict] = None
    reasons: tuple = ()


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _role_conflicts(
    signer: Issuer, permit: dict, tool_receipts: list, reconciliation: dict,
    approval: Optional[dict],
) -> list:
    conflicts = []
    if signer.identity == permit.get("issuer") or signer.key_id == permit.get("key_id"):
        conflicts.append(
            "role separation: assurance-signer identity/key must differ from the permit issuer"
        )
    if signer.identity == reconciliation.get("issuer") or signer.key_id == reconciliation.get("key_id"):
        conflicts.append(
            "role separation: assurance-signer identity/key must differ from the reconciler "
            "-- certify() trusts the Reconciliation's signed certified flag rather than "
            "re-deriving it, so the reconciler and certifier must be distinct identities"
        )
    for receipt in tool_receipts:
        executor = receipt.get("executor") or {}
        if signer.identity and signer.identity == executor.get("id"):
            conflicts.append(
                f"role separation: assurance-signer identity must differ from tool executor "
                f"{executor.get('id')!r}"
            )
        if signer.identity == receipt.get("issuer") or signer.key_id == receipt.get("key_id"):
            conflicts.append(
                "role separation: assurance-signer identity/key must differ from the "
                "tool-receipt recorder"
            )
    if approval is not None:
        approver = approval.get("approver") or {}
        if signer.identity == approver.get("id"):
            conflicts.append(
                f"role separation: assurance-signer identity must differ from the approver "
                f"{approver.get('id')!r}"
            )
    return conflicts


def _find_discharge(
    obligation_id: str, action_digest: str, discharge_receipts: list,
    *, trust_store: TrustStore, revocation_store: Optional[RevocationStore], reference: datetime,
) -> Optional[dict]:
    for candidate in discharge_receipts:
        if not isinstance(candidate, dict):
            continue
        if candidate.get("obligation_id") != obligation_id:
            continue
        if candidate.get("action_digest") != action_digest:
            continue
        result = verify(
            candidate, "ObligationDischargeReceipt",
            trust_store=trust_store, revocation_store=revocation_store, now=reference,
        )
        if result.ok:
            return candidate
    return None


def certify(
    permit: dict,
    tool_receipts: Iterable[dict],
    reconciliation: dict,
    *,
    trust_store: TrustStore,
    revocation_store: Optional[RevocationStore] = None,
    discharge_receipts: Iterable[dict] = (),
    blocking_obligations: Iterable[str] = (),
    mandatory_sources: Iterable[str] = (),
    freshness: Optional[FreshnessPort] = None,
    approval: Optional[dict] = None,
    signer: Issuer,
    certifier_role: str = "assurance-signer",
    run_id: str,
    nonce: str,
    prev_digest: Optional[str] = None,
    now: Optional[datetime] = None,
    schema_version: str = "1.0.0",
    certificate_ttl: timedelta = DEFAULT_CERTIFICATE_TTL,
) -> CertificationResult:
    if not isinstance(permit, dict):
        return CertificationResult(False, None, ("permit is not a JSON object",))
    if not isinstance(reconciliation, dict):
        return CertificationResult(False, None, ("reconciliation is not a JSON object",))

    reference = _as_utc(now) if now is not None else datetime.now(timezone.utc)

    # 1. permit: never retroactively admit.
    permit_verified = verify(
        permit, "ExecutionPermit",
        trust_store=trust_store, revocation_store=revocation_store, now=reference,
    )
    if not permit_verified.ok:
        return CertificationResult(False, None, permit_verified.errors)
    if permit.get("enforcement_grade") not in ("mediated", "platform"):
        return CertificationResult(False, None, (
            f"enforcement_grade {permit.get('enforcement_grade')!r} is not enforcement "
            "-- cannot certify",
        ))
    action_digest = permit.get("action_digest")

    # 2. tool receipts: complete and verified.
    receipts = list(tool_receipts)
    if not receipts:
        return CertificationResult(False, None, (
            "no tool receipts: nothing was dispatched -- a successful tool exit alone "
            "(or no exit at all) cannot certify",
        ))
    verified_receipts = []
    for receipt in receipts:
        if not isinstance(receipt, dict):
            return CertificationResult(False, None, ("a tool receipt is not a JSON object",))
        result = verify(
            receipt, "ToolReceipt",
            trust_store=trust_store, revocation_store=revocation_store, now=reference,
        )
        if not result.ok:
            return CertificationResult(False, None, result.errors)
        if receipt.get("action_digest") != action_digest:
            return CertificationResult(False, None, (
                f"tool receipt for {receipt.get('tool')!r} does not bind this permit's action_digest",
            ))
        verified_receipts.append(receipt)

    # 3. reconciliation: must itself verify, bind this run, and be clean.
    reconciliation_verified = verify(
        reconciliation, "Reconciliation",
        trust_store=trust_store, revocation_store=revocation_store, now=reference,
    )
    if not reconciliation_verified.ok:
        return CertificationResult(False, None, reconciliation_verified.errors)
    if reconciliation.get("action_digest") != action_digest:
        return CertificationResult(False, None, (
            "reconciliation does not bind this permit's action_digest",
        ))
    if (
        reconciliation.get("state") != "RECONCILED"
        or reconciliation.get("certified") is not True
        or reconciliation.get("residuals")
        or reconciliation.get("invalid_receipts")
    ):
        return CertificationResult(False, None, (
            "reconciliation is not a clean, matching, certifiable record -- a mismatched or "
            "residual-open reconciliation cannot certify",
        ))

    # 4. every blocking obligation needs verified discharge evidence.
    discharge_pool = [d for d in discharge_receipts if isinstance(d, dict)]
    reasons: list = []
    discharged_digests: list = []
    for obligation_id in blocking_obligations:
        found = _find_discharge(
            obligation_id, action_digest, discharge_pool,
            trust_store=trust_store, revocation_store=revocation_store, reference=reference,
        )
        if found is None:
            reasons.append(
                f"blocking obligation {obligation_id!r} is not discharged "
                "(no verified ObligationDischargeReceipt bound to this action)"
            )
        else:
            discharged_digests.append(canonical.subject_digest(found))

    # 5. mandatory sources must be fresh.
    mandatory = list(mandatory_sources)
    if mandatory and freshness is None:
        reasons.append("mandatory sources declared but no freshness port was supplied")
    elif freshness is not None:
        for source_id in mandatory:
            if not freshness.is_fresh(source_id, at=reference):
                reasons.append(f"stale mandatory source: {source_id!r}")

    # 6. role separation.
    reasons.extend(_role_conflicts(signer, permit, verified_receipts, reconciliation, approval))

    if reasons:
        return CertificationResult(False, None, tuple(reasons))

    issued = reference
    certificate = {
        "schema_version": schema_version,
        "type": "OversightCertificate",
        "issuer": signer.identity,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + certificate_ttl).isoformat(),
        "run_id": run_id,
        "nonce": nonce,
        "key_id": signer.key_id,
        "action_digest": action_digest,
        "permit_digest": canonical.subject_digest(permit),
        "reconciliation_digest": canonical.subject_digest(reconciliation),
        "tool_receipt_digests": [canonical.subject_digest(r) for r in verified_receipts],
        "discharged_obligation_digests": discharged_digests,
        "certifier": {"id": signer.identity, "role": certifier_role},
    }
    if prev_digest is not None:
        certificate["prev_digest"] = prev_digest
    certificate["subject_digest"] = canonical.subject_digest(certificate)
    certificate["signature"] = signer.sign(certificate)
    return CertificationResult(True, certificate, ())
