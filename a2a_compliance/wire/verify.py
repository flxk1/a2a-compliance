"""Pure E0 verifier: schema validate + canonical digest recompute + fail-closed
checks. Does NOT verify `signature` (E1). Does NOT decide admission (E2). No
host effect: no dispatch, no network, no file I/O beyond the packaged schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Protocol

from ..lifecycle import TOOL_OWNERS
from . import canonical
from .schema_registry import WIRE_TYPES, validator_for


class NonceStore(Protocol):
    """Injected port (E0 defines the interface; a host supplies a durable
    implementation). Scoped by (run_id, nonce): the same nonce value issued
    under two different runs is not a replay of either."""

    def seen(self, run_id: str, nonce: str) -> bool: ...

    def record(self, run_id: str, nonce: str) -> None: ...


class InMemoryNonceStore:
    """Test-only in-memory NonceStore. Not durable; never use in a host."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()

    def seen(self, run_id: str, nonce: str) -> bool:
        return (run_id, nonce) in self._seen

    def record(self, run_id: str, nonce: str) -> None:
        self._seen.add((run_id, nonce))


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


def verify(
    obj: dict,
    obj_type: str,
    *,
    nonce_store: Optional[NonceStore] = None,
    now: Optional[datetime] = None,
) -> VerificationResult:
    """Validate `obj` as a wire `obj_type`. Fail-closed: any error rejects the
    whole object; nothing here ever returns ok=True on ambiguity."""
    if obj_type not in WIRE_TYPES:
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

    expires_at = _parse_datetime(obj.get("expires_at"))
    if expires_at is None:
        errors.append("expires_at is not a parseable date-time")
    else:
        reference = now if now is not None else datetime.now(timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        if expires_at <= reference:
            errors.append("expires_at is in the past (stale)")

    if obj_type == "StageReceipt":
        errors.extend(_stage_receipt_role_findings(obj))

    if nonce_store is not None:
        run_id, nonce = obj.get("run_id"), obj.get("nonce")
        if nonce_store.seen(run_id, nonce):
            errors.append("nonce replay: (run_id, nonce) already consumed")

    if errors:
        return VerificationResult(False, tuple(errors))

    if nonce_store is not None:
        # Consume only on a fully passing verification, so an attacker
        # cannot burn a legitimate nonce by submitting a garbage object.
        nonce_store.record(obj["run_id"], obj["nonce"])

    return VerificationResult(True, ())
