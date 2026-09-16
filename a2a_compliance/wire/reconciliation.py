"""E4 -- verified reconciliation (plan: 'effect-reconciliation' -- "Intended
versus observed comparison"; state machine: "Certification requires admitted
dispatch, complete tool receipts and matching observed effects. Reconciliation
may never retroactively admit execution.").

`reconcile` is the ONLY function in this package that compares intended
against observed effects. It VERIFIES the permit and every `ToolReceipt`
through E1 `wire.verification.verify` before trusting any of their fields --
same discipline as E2's `admission.admit` and E3's `consume_and_execute`. It
never fabricates an effect: OBSERVED effects arrive only via the injected,
host-owned `ObservedEffects` (fixed trust boundary) -- this module has no
network/file/subprocess access of its own, and a `ToolReceipt`'s own
self-reported `effect_digest` is never, by itself, sufficient evidence (that
is exactly the "a successful tool exit alone cannot certify" property, plan:
'E4 exit').

Never retroactively admits: if the permit does not `verify()` (missing,
forged, wrong-key, expired, revoked) or was never issued at an enforcement
grade, `reconcile` produces NO signed `Reconciliation` object at all --
there is nothing legitimate to reconcile. Once the permit itself checks out,
`reconcile` ALWAYS produces and signs a `Reconciliation` record (matching the
`reconciliation.schema.json` shape, which requires `missing_receipts`/
`open_receipts`/`failed_receipts`/`invalid_receipts`/`reason` on every
instance) -- a residual-open outcome is a real, auditable, signed finding,
not a Python-level rejection.

Design decision surfaced for human confirmation (mirrors `wire/signing.py`'s
convention): `reconciliation.schema.json`'s `state` enum reuses
`lifecycle.RunState`'s values and has no `RESIDUAL_OPEN`/`OBSERVED` member
(the schema's own docstring already flags this as a known discrepancy against
the plan's prose state-machine names) -- adding one would change an
already-published schema's shape, which this slice must not do. This module
resolves it by always setting `state="RECONCILED"` on a produced object and
carrying the plan's OBSERVED/RECONCILED/CERTIFIED/RESIDUAL_OPEN distinction
in the already-existing, now load-bearing `certified` (bool) and `residuals`
(array) fields instead: `certified=True` here means "this reconciliation's
own scope (effects) is clean" -- necessary but NOT sufficient for actual
certification, which additionally needs discharged blocking obligations and
fresh mandatory sources; see `wire/certification.py`, which never trusts this flag
alone and re-verifies the object from scratch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from . import canonical
from .admission import Issuer
from .trust import RevocationStore, TrustStore
from .verification import verify

DEFAULT_RECONCILIATION_TTL = timedelta(days=365)


@dataclass(frozen=True)
class ObservedEffects:
    """Host-owned port input (fixed trust boundary): the run's independently
    observed effects. `effects` maps a `ToolReceipt`'s own `subject_digest`
    to the effect the host actually observed for that dispatch -- NOT
    derived from the receipt itself, so a compromised or lying executor's
    self-reported `ToolReceipt.effect_digest` is never the only source of
    truth. `unmatched` lists any effect the host observed with no
    corresponding receipt at all (something happened that no receipt
    explains)."""

    effects: dict = field(default_factory=dict)
    unmatched: tuple = ()


@dataclass(frozen=True)
class ReconciliationResult:
    ok: bool
    reconciliation: Optional[dict] = None
    reasons: tuple = ()


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def reconcile(
    permit: dict,
    tool_receipts: Iterable[dict],
    observed: ObservedEffects,
    *,
    trust_store: TrustStore,
    revocation_store: Optional[RevocationStore] = None,
    signer: Issuer,
    run_id: str,
    nonce: str,
    intended_effects: Optional[dict] = None,
    now: Optional[datetime] = None,
    schema_version: str = "1.0.0",
    reconciliation_ttl: timedelta = DEFAULT_RECONCILIATION_TTL,
) -> ReconciliationResult:
    """Verify `permit` and every `tool_receipts` entry, compare their
    self-reported effects against `observed` (and, where declared, against
    `intended_effects`), and sign the resulting `Reconciliation`.

    `intended_effects`, if given, maps a tool name to the effect dict that
    was declared intended for it (e.g. bound into the permit's `constraints`
    at admission time); a verified receipt for that tool whose own
    `effect_digest` does not match the intended one is a residual, even if
    the host also independently observed exactly that (wrong) effect --
    catching "the tool ran and self-consistently reported an effect, but not
    the intended one", not only "the tool lied about what it did".
    """
    if not isinstance(permit, dict):
        return ReconciliationResult(False, None, ("permit is not a JSON object",))

    reference = _as_utc(now) if now is not None else datetime.now(timezone.utc)

    # Never retroactively admit: no legitimate permit, no reconciliation.
    verified = verify(
        permit, "ExecutionPermit",
        trust_store=trust_store, revocation_store=revocation_store, now=reference,
    )
    if not verified.ok:
        return ReconciliationResult(False, None, verified.errors)

    grade = permit.get("enforcement_grade")
    if grade not in ("mediated", "platform"):
        return ReconciliationResult(False, None, (
            f"enforcement_grade {grade!r} is not enforcement -- cannot reconcile to certifiable",
        ))

    action_digest = permit.get("action_digest")
    invalid: list = []
    verified_receipts: list = []
    for receipt in tool_receipts:
        if not isinstance(receipt, dict):
            invalid.append("tool receipt is not a JSON object")
            continue
        result = verify(
            receipt, "ToolReceipt",
            trust_store=trust_store, revocation_store=revocation_store, now=reference,
        )
        label = receipt.get("tool", "?")
        if not result.ok:
            invalid.append(f"{label}: " + "; ".join(result.errors))
            continue
        if receipt.get("action_digest") != action_digest:
            invalid.append(f"{label}: action_digest does not bind to this permit")
            continue
        verified_receipts.append(receipt)

    intended_map = dict(intended_effects or {})
    observed_map = dict(observed.effects) if observed is not None else {}
    unmatched = tuple(observed.unmatched) if observed is not None else ()

    residuals: list = []
    for receipt in verified_receipts:
        digest = canonical.subject_digest(receipt)
        tool = receipt.get("tool")
        self_reported = receipt.get("effect_digest")
        seen = observed_map.get(digest)
        if seen is None:
            residuals.append(f"missing observed effect for tool {tool!r} (receipt {digest!r})")
        elif canonical.digest_hex(seen) != self_reported:
            residuals.append(
                f"effect mismatch for tool {tool!r}: host-observed effect does not match "
                "the receipt's self-reported effect_digest"
            )
        if tool in intended_map and canonical.digest_hex(intended_map[tool]) != self_reported:
            residuals.append(
                f"intended/observed mismatch for tool {tool!r}: executed effect does not "
                "match the effect declared intended for it"
            )

    for extra in unmatched:
        residuals.append(f"unexpected effect with no matching receipt: {canonical.digest_hex(extra)!r}")

    delivered_tools = {r.get("tool") for r in verified_receipts}
    missing_tools = tuple(sorted(set(intended_map) - delivered_tools))
    for tool in missing_tools:
        residuals.append(f"missing tool receipt for intended tool {tool!r}")

    if not verified_receipts:
        residuals.append("no verified tool receipts: nothing was dispatched to reconcile")

    certified = not invalid and not residuals and bool(verified_receipts)
    reason = (
        "effects matched: reconciliation is clean and certifiable" if certified
        else "residual open: " + "; ".join(residuals or invalid)
    )

    observed_all = {digest: canonical.digest_hex(effect) for digest, effect in observed_map.items()}
    observed_effects_digest = canonical.digest_hex({
        "effects": observed_all,
        "unmatched": [canonical.digest_hex(e) for e in unmatched],
    })
    intended_effects_digest = canonical.digest_hex(intended_map)

    issued = reference
    reconciliation = {
        "schema_version": schema_version,
        "type": "Reconciliation",
        "issuer": signer.identity,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + reconciliation_ttl).isoformat(),
        "run_id": run_id,
        "nonce": nonce,
        "key_id": signer.key_id,
        "state": "RECONCILED",
        "certified": certified,
        "action_digest": action_digest,
        "missing_receipts": list(missing_tools),
        "open_receipts": [],
        "failed_receipts": [],
        "invalid_receipts": list(invalid),
        "reason": reason,
        "intended_effects_digest": intended_effects_digest,
        "observed_effects_digest": observed_effects_digest,
        "discharged_obligations": [],
        "residuals": list(residuals),
    }
    reconciliation["subject_digest"] = canonical.subject_digest(reconciliation)
    reconciliation["signature"] = signer.sign(reconciliation)
    return ReconciliationResult(True, reconciliation, ())
