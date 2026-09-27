"""E1 trust ports: TrustStore (key_id -> Ed25519 public key + role/type
authorization) and RevocationStore (key/policy/permit/run revocation).

Pure Python -- no `cryptography` import here; only `wire/signing.py` touches
that package. Trust roots and role bindings are deployment configuration
(plan: 'Wire contracts'), never read from an object's own payload: a host
builds and injects these. This module only declares the port shape and
offers in-memory TEST-ONLY implementations.

Fail-closed by construction: a `TrustBinding` grants no object type and no
role unless explicitly listed. There is no wildcard default -- a caller who
wants a key bound to "any type" must pass that set explicitly, so a bare
`TrustBinding(public_key, frozenset(), frozenset())` (or an unresolved
key_id) authorizes nothing.

Key-bound identity: `TrustBinding.identity` is the principal name (deployment
config, injected the same way as `object_types`/`roles`, never read from an
object's own payload) that this key is bound to speak for -- e.g. the actual
human behind a `HumanApprovalReceipt`, the actual policy author behind a
signed `GovernanceBlock`, the actual role-holder behind a `StageReceipt`.
Backward compatibility is deliberately narrow: a binding built with
`identity=None` (the default -- every `InMemoryTrustStore.add()` call that
predates this field, and any caller outside this package's territory that
never passes `identity=`, keeps behaving exactly as before) still resolves,
still authorizes object types via `authorizes_type`, still authorizes
StageReceipt roles via `authorizes_role`, and a signature under it still
verifies -- none of E0/E1's original type/role/signature checks read
`identity` at all. But a distinct, NEWER class of check -- one that answers
"WHO signed this", not just "did a key of the right type/role sign this" --
depends on `identity` by construction, and for those checks a `None`
identity is not "check skipped", it is "check fails": an identity-less
binding can prove "some key authorized for this type/role signed this",
never "principal X signed this". Concretely, `verification.
verify_human_approval` (a HumanApprovalReceipt's `approver.id`),
`admission._governance_block_findings` (a signed GovernanceBlock's author),
and `verification._trust_findings` for `StageReceipt` (its `issuer`) all
reject when the resolved binding's `identity` is `None`, exactly as they
reject on an outright identity mismatch -- there is no silent pass-through.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol

ANY = "*"


@dataclass(frozen=True)
class TrustBinding:
    """A key_id's trust: its raw 32-byte Ed25519 public key, and the wire
    object types / StageReceipt roles it is authorized to issue. Pass
    `frozenset({trust.ANY})` for either set to mean "any" -- do so
    deliberately, never by relying on a default."""

    public_key: bytes
    object_types: frozenset[str]
    roles: frozenset[str]
    identity: Optional[str] = None

    def authorizes_type(self, obj_type: str) -> bool:
        return ANY in self.object_types or obj_type in self.object_types

    def authorizes_role(self, role: Optional[str]) -> bool:
        return ANY in self.roles or role in self.roles


class TrustStore(Protocol):
    """Injected port. Resolves a signing key_id to its trust binding. A
    key_id absent from the store is UNTRUSTED -- resolve() returns None,
    never a default/wildcard binding."""

    def resolve(self, key_id: str) -> Optional[TrustBinding]: ...


class InMemoryTrustStore:
    """TEST-ONLY in-memory TrustStore. Not durable; never use in a host."""

    def __init__(self) -> None:
        self._bindings: dict[str, TrustBinding] = {}

    def add(
        self,
        key_id: str,
        public_key: bytes,
        object_types: frozenset[str],
        roles: frozenset[str],
        identity: Optional[str] = None,
    ) -> None:
        """`identity` is keyword-optional and defaults to `None` so every
        pre-existing call site (inside and outside this package) keeps
        registering identity-less bindings unchanged; see `TrustBinding`'s
        docstring for exactly which checks then fail closed."""
        self._bindings[key_id] = TrustBinding(
            public_key, frozenset(object_types), frozenset(roles), identity,
        )

    def resolve(self, key_id: str) -> Optional[TrustBinding]:
        return self._bindings.get(key_id)


class RevocationStore(Protocol):
    """Injected port. `revoked_type` is one of "key"/"policy"/"permit"/"run"
    (matches revocation.schema.json's `revoked_type`); `revoked_id` its
    key_id / policy digest / permit action_digest / run_id. `at` is the
    verification reference time; a revocation effective in the future does
    not yet apply."""

    def is_revoked(self, revoked_type: str, revoked_id: str, *, at: datetime) -> bool: ...


class InMemoryRevocationStore:
    """TEST-ONLY in-memory RevocationStore. Not durable; never use in a
    host. A real store should only ever be populated from Revocation wire
    objects that have THEMSELVES already passed `wire.verification` -- an
    unverified revocation claim must not be trusted; `record()` below
    assumes its caller already did that."""

    def __init__(self) -> None:
        self._entries: list[tuple[str, str, datetime]] = []

    def revoke(self, revoked_type: str, revoked_id: str, effective_at: datetime) -> None:
        self._entries.append((revoked_type, revoked_id, effective_at))

    def record(self, revocation_obj: dict) -> None:
        """Convenience: load straight from an (already-verified) Revocation
        wire object's own fields."""
        effective_at = revocation_obj["effective_at"]
        if isinstance(effective_at, str):
            text = effective_at[:-1] + "+00:00" if effective_at.endswith("Z") else effective_at
            effective_at = datetime.fromisoformat(text)
        self.revoke(revocation_obj["revoked_type"], revocation_obj["revoked_id"], effective_at)

    def is_revoked(self, revoked_type: str, revoked_id: str, *, at: datetime) -> bool:
        return any(
            t == revoked_type and i == revoked_id and eff <= at
            for t, i, eff in self._entries
        )
