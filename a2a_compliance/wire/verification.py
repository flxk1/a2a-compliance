"""Pure verifier: schema validate + canonical digest recompute + fail-closed
checks (E0), plus E1's DSSE/Ed25519 signature verification, trust-role
bindings and revocation -- both engage ONLY when their store is passed in,
so `verify()` with no `trust_store`/`revocation_store` is byte-for-byte the
E0 behavior (signature stays opaque). Does NOT decide admission (E2). No
host effect: no dispatch, no network, no file I/O beyond the packaged
schemas; no `cryptography` import at module load time (see `wire/signing.py`
-- it is imported here only inside `_trust_findings`, i.e. only when a
`trust_store` is actually supplied).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Optional, Protocol

from ..lifecycle import TOOL_OWNERS
from . import canonical
from .schema_registry import ALL_WIRE_TYPES, validator_for
from .trust import RevocationStore, TrustStore


class NonceStore(Protocol):
    """Injected port (E0 defines the interface; a host supplies a durable
    implementation). Scoped by (run_id, nonce): the same nonce value issued
    under two different runs is not a replay of either.

    `seen`/`record` (E0/E1) are a two-step check-then-write used by
    `verify()`'s optional replay check and by E2's `issue_permit` single-use
    nonce guard -- not atomic by contract, fine for those callers because
    nothing else races them in this package.

    `consume` (E3) is DISTINCT: a single atomic compare-and-set a host
    implements durably (e.g. one conditional UPDATE) -- `True` the first
    time a given `(run_id, nonce)` is consumed, `False` on every call after
    that, including concurrent/racing ones. `wire.executor.consume_and_execute`
    calls ONLY `consume`, never `seen`/`record`, so an ExecutionPermit's
    nonce has exactly one guarded consumption path before dispatch (plan:
    'The host atomically consumes the nonce before dispatch. A second
    consumption fails.')."""

    def seen(self, run_id: str, nonce: str) -> bool: ...

    def record(self, run_id: str, nonce: str) -> None: ...

    def consume(self, run_id: str, nonce: str) -> bool: ...


class InMemoryNonceStore:
    """Test-only in-memory NonceStore. Not durable; never use in a host.
    `consume` uses its own lock and its own set, independent of
    `seen`/`record`'s bookkeeping -- the two mechanisms guard different
    nonce usages (E0/E1 replay-of-a-signed-object vs. E3 single-use
    dispatch) and must not be conflated even in this test double."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()
        self._consumed: set[tuple[str, str]] = set()
        self._lock = Lock()

    def seen(self, run_id: str, nonce: str) -> bool:
        return (run_id, nonce) in self._seen

    def record(self, run_id: str, nonce: str) -> None:
        self._seen.add((run_id, nonce))

    def consume(self, run_id: str, nonce: str) -> bool:
        key = (run_id, nonce)
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    errors: tuple[str, ...] = field(default=())


def _parse_datetime(value: object) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _stage_receipt_role_findings(obj: dict) -> list[str]:
    capability = obj.get("capability")
    if not isinstance(capability, str) or not capability.startswith("tool:"):
        return []
    key = capability.removeprefix("tool:")
    owner = TOOL_OWNERS.get(key)
    if owner is None:
        return []  # not a tool this family owns; role authority is out of E0 scope
    if obj.get("role") != owner:
        return [f"wrong-role: {key!r} is owned by role {owner!r}, not {obj.get('role')!r}"]
    return []


def _trust_findings(obj: dict, obj_type: str, trust_store: TrustStore) -> list[str]:
    """E1: the signing key_id must resolve, be bound to this object's type,
    and (for StageReceipt) its role, THEN the signature itself must verify.
    Trust roots/bindings come only from `trust_store` (deployment config),
    never from the object's own payload."""
    key_id = obj.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        return ["signature verification failed: key_id is empty or not a string"]

    binding = trust_store.resolve(key_id)
    if binding is None:
        return [f"unknown key_id: {key_id!r} is not resolvable by the trust store"]
    if not binding.authorizes_type(obj_type):
        return [f"key not bound to object type: {key_id!r} is not authorized to issue {obj_type!r}"]
    if obj_type == "StageReceipt" and not binding.authorizes_role(obj.get("role")):
        return [f"key not bound to role: {key_id!r} is not authorized to issue role {obj.get('role')!r}"]

    from . import signing  # local: only import `cryptography`'s dependency when a trust_store is actually used

    return signing.verify_signature(obj, binding.public_key)


def _revocation_findings(
    obj: dict, obj_type: str, revocation_store: RevocationStore, reference: datetime,
) -> list[str]:
    """E1: reject an object whose key_id / run_id / permit (action_digest or
    permitted_action_digest) -- or, for ContextManifest, policy bundle -- is
    revoked as of `reference`."""
    findings: list[str] = []

    key_id = obj.get("key_id")
    if isinstance(key_id, str) and revocation_store.is_revoked("key", key_id, at=reference):
        findings.append(f"revoked: key_id {key_id!r} is revoked as of {reference.isoformat()}")

    run_id = obj.get("run_id")
    if isinstance(run_id, str) and revocation_store.is_revoked("run", run_id, at=reference):
        findings.append(f"revoked: run_id {run_id!r} is revoked as of {reference.isoformat()}")

    permit_digest = obj.get("action_digest") or obj.get("permitted_action_digest")
    if isinstance(permit_digest, str) and revocation_store.is_revoked("permit", permit_digest, at=reference):
        findings.append(f"revoked: permit {permit_digest!r} is revoked as of {reference.isoformat()}")

    if obj_type == "ContextManifest":
        policy_digest = obj.get("policy_bundle_digest")
        if isinstance(policy_digest, str) and revocation_store.is_revoked("policy", policy_digest, at=reference):
            findings.append(f"revoked: policy {policy_digest!r} is revoked as of {reference.isoformat()}")

    return findings


def verify(
    obj: dict,
    obj_type: str,
    *,
    nonce_store: Optional[NonceStore] = None,
    trust_store: Optional[TrustStore] = None,
    revocation_store: Optional[RevocationStore] = None,
    now: Optional[datetime] = None,
) -> VerificationResult:
    """Validate `obj` as a wire `obj_type`. Fail-closed: any error rejects the
    whole object; nothing here ever returns ok=True on ambiguity.

    `trust_store`/`revocation_store` are E1 ports: omit both and this is the
    E0 verifier (signature opaque, no revocation check) byte-for-byte."""
    if obj_type not in ALL_WIRE_TYPES:
        return VerificationResult(False, (f"unknown type: {obj_type!r}",))
    if not isinstance(obj, dict):
        return VerificationResult(False, ("object is not a JSON object",))

    errors: list[str] = []
    if obj.get("type") != obj_type:
        errors.append(f"type mismatch: expected {obj_type!r}, found {obj.get('type')!r}")

    validator = validator_for(obj_type)
    schema_errors = sorted(
        (f"schema: {e.json_path}: {e.message}" for e in validator.iter_errors(obj)),
    )
    errors.extend(schema_errors)
    if errors:
        # A schema-invalid object has no reliable shape to canonicalise or
        # stage-check further; report what schema validation found and stop.
        return VerificationResult(False, tuple(errors))

    try:
        expected_digest = canonical.subject_digest(obj)
    except (TypeError, ValueError) as exc:
        return VerificationResult(False, (f"cannot canonicalise object: {exc}",))
    if obj.get("subject_digest") != expected_digest:
        errors.append("subject_digest mismatch: recomputed digest does not match the claimed digest")

    reference = now if now is not None else datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    expires_at = _parse_datetime(obj.get("expires_at"))
    if expires_at is None:
        errors.append("expires_at is not a parseable date-time")
    elif expires_at <= reference:
        errors.append("expires_at is in the past (stale)")

    if obj_type == "StageReceipt":
        errors.extend(_stage_receipt_role_findings(obj))

    if nonce_store is not None:
        run_id, nonce = obj.get("run_id"), obj.get("nonce")
        if nonce_store.seen(run_id, nonce):
            errors.append("nonce replay: (run_id, nonce) already consumed")

    if trust_store is not None:
        errors.extend(_trust_findings(obj, obj_type, trust_store))

    if revocation_store is not None:
        errors.extend(_revocation_findings(obj, obj_type, revocation_store, reference))

    if errors:
        return VerificationResult(False, tuple(errors))

    if nonce_store is not None:
        # Consume only on a fully passing verification, so an attacker
        # cannot burn a legitimate nonce by submitting a garbage object.
        nonce_store.record(obj["run_id"], obj["nonce"])

    return VerificationResult(True, ())
