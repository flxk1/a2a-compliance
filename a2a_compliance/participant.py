"""Maker-side control-participant shim — cooperative poll (SPEC §9, §11).

THE load-bearing piece. A fresh-hire maker does not expose a live inbound
channel today; this shim bridges the gap by having the maker poll a
session-keyed inbox at its own turn boundaries / checkpoints and honour any
pending directive.

Honest limitation (SPEC §9, §11): this is a COOPERATIVE mechanism. A directive
is delivered only when the maker reaches `checkpoint()`, and a `halt` is a
cooperative stop at the next checkpoint — NOT a forced kill. A forced stop is a
harness/external enforcement capability the bare protocol cannot promise. The maker's own loop
must consult `should_continue()` / `is_held()` and yield; a maker that never
checkpoints cannot be steered by this shim.

The three Protocol methods (`accept_directive`, `report_state`, `halt`) are the
direct handlers; `checkpoint()` drains the inbox, dispatches each polled message
to the matching handler, and posts the response back to the compliance actor.

--- Authenticated control channel (OWASP ASI07) --------------------------

Two modes, chosen entirely by whether a `TrustStore` is configured:

- BARE/ADVISORY (`trust_store is None`, the Phase-1 default): any envelope in
  the mailbox is read and, if otherwise well-formed, honoured — but every
  honoured message is reported back labelled `"mode": "advisory"` /
  `"authenticated": False`. An unsigned envelope is never silently treated as
  trustworthy; it is only ever advisory.
- AUTHENTICATED (`trust_store` configured on this participant): a message is
  honoured ONLY if it verifies — signed by a key the `TrustStore` resolves and
  binds to this envelope type and the sender's claimed role, not expired, not
  a replayed `(sender, nonce)` pair (checked via the injected `NonceStore`
  port), and the sender's role is `authorize()`-authorized for the verb. Any
  failure — unsigned, unverifiable, expired, replayed, unauthorized, or (fail
  closed) `cryptography` itself being unavailable — REJECTS the message: it is
  never applied, and the maker reports it back as `ack{accepted: False}` with
  a reason. Signature verification reuses `wire/signing.py` exclusively (no
  Ed25519/cryptography code is duplicated here); the trust roster and replay
  guard reuse `wire/trust.py` / `wire/verification.py`'s ports, injected —
  never read from the envelope's own claimed fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from interfaces.a2a_control import Verb, Party, Authority, Message
from . import envelope as env
from .authority import Roster, authorize
from .inbox import FileInbox
from .nonce_store import FileNonceStore, safe_component

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from .wire.trust import TrustStore
    from .wire.verification import NonceStore


StateProvider = Callable[[list[str]], dict]

# The wire-object-type string a TrustStore's key bindings authorize for the
# A2A control channel (distinct from the E1 wire types in schema_registry.py
# -- the control envelope is its own schema, not one of those eight).
ENVELOPE_OBJECT_TYPE = "A2AControlMessage"


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


@dataclass(frozen=True)
class _EnvelopeVerdict:
    ok: bool
    advisory: bool
    reason: str


@dataclass
class DirectiveRecord:
    directive_id: str
    kind: str
    instruction: str


@dataclass
class ControlParticipant:
    """A maker that participates in the A2A control channel by polling.

    `state_provider(include)` returns the maker's current state for the
    requested dimensions (mandate/trajectory/tools/claims); its output is always
    reported at the self-report tier."""

    session_id: str
    inbox: FileInbox
    compliance_actor: str
    role: str = "maker"
    state_provider: Optional[StateProvider] = None
    trust_store: Optional["TrustStore"] = None
    nonce_store: Optional["NonceStore"] = None
    roster: Optional[Roster] = None

    _halted: bool = field(default=False, init=False)
    _held: bool = field(default=False, init=False)
    _hold_ref: Optional[str] = field(default=None, init=False)
    _hold_conditions: list[str] = field(default_factory=list, init=False)
    directives: list[DirectiveRecord] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        """FIX 2(c): AUTHENTICATED mode (`trust_store` configured) must never
        silently skip the replay check just because a caller did not inject
        its own `nonce_store` -- that fail-open gap is exactly what the
        recorded `replay.py` exploit relied on. When no `nonce_store` is
        given, default to a durable `FileNonceStore` scoped under this
        participant's own inbox root -- never leave `nonce_store` `None` in
        authenticated mode. See `nonce_store.py` for why a durable default
        was chosen over an outright rejection."""
        if self.trust_store is not None and self.nonce_store is None:
            # `inbox` is typed `FileInbox` (durable, has `.root`); a caller
            # that duck-types in a non-durable inbox stand-in (e.g. an
            # in-memory test double) has no durable root to scope a default
            # under -- fall back to a fresh, process-local temp directory
            # rather than crash, so this default never becomes a reason to
            # reject envelopes it should otherwise accept.
            root_hint = getattr(self.inbox, "root", None)
            if root_hint is not None:
                default_root = Path(root_hint) / ".nonces" / safe_component(self.session_id)
            else:
                import tempfile

                default_root = Path(tempfile.mkdtemp(prefix="a2a-nonce-"))
            self.nonce_store = FileNonceStore(default_root)

    # --- cooperative-stop signals the maker's own loop consults --------------

    def should_continue(self) -> bool:
        """False once a `halt` has been honoured. The maker's loop MUST consult
        this at each checkpoint and stop cooperatively when it is False."""
        return not self._halted

    def is_held(self) -> bool:
        return self._held

    @property
    def halted(self) -> bool:
        return self._halted

    # --- authenticated-channel verification (OWASP ASI07) ---------------------

    @property
    def authenticated_mode(self) -> bool:
        """True when a `TrustStore` is configured -- AUTHENTICATED mode. False
        (BARE/ADVISORY) is the Phase-1 default: no trust store means every
        envelope is read but honoured only as advisory."""
        return self.trust_store is not None

    def _verify_envelope(self, wire: dict, msg: Message) -> _EnvelopeVerdict:
        if not self.authenticated_mode:
            return _EnvelopeVerdict(
                True, advisory=True,
                reason="bare mode: no trust store configured; unsigned envelope "
                "read and honoured as advisory only",
            )

        signature = wire.get("signature")
        key_id = wire.get("key_id")
        if not signature or not key_id:
            return _EnvelopeVerdict(
                False, advisory=False,
                reason="unsigned envelope rejected in authenticated mode",
            )

        binding = self.trust_store.resolve(key_id)
        if binding is None:
            return _EnvelopeVerdict(
                False, advisory=False,
                reason=f"unknown key_id {key_id!r}: not resolvable by the trust store",
            )
        if not binding.authorizes_type(ENVELOPE_OBJECT_TYPE):
            return _EnvelopeVerdict(
                False, advisory=False,
                reason=f"key {key_id!r} is not authorized to issue control envelopes",
            )
        if not binding.authorizes_role(msg.from_.role):
            return _EnvelopeVerdict(
                False, advisory=False,
                reason=f"key {key_id!r} is not authorized for role {msg.from_.role!r}",
            )
        # FIX 1(a): the envelope's claimed sender must equal the signing
        # key's bound identity -- a self-declared `from_.actor` is never
        # trusted on its own (the same key-bound-identity posture the
        # identity leg already applies to `HumanApprovalReceipt.approver`
        # and `GovernanceBlock` authorship). A `None`-identity binding fails
        # closed here too, exactly per `trust.TrustBinding`'s docstring --
        # it is "check fails", never "check skipped".
        if binding.identity is None or binding.identity != msg.from_.actor:
            return _EnvelopeVerdict(
                False, advisory=False,
                reason=(
                    f"key {key_id!r} is bound to identity {binding.identity!r}, "
                    f"not the envelope's claimed sender {msg.from_.actor!r}"
                ),
            )

        try:
            from .wire import signing  # local: only requires `cryptography` here
            errors = signing.verify_signature(wire, binding.public_key)
        except ImportError:
            # Fail closed (contract): with no `cryptography` extra installed,
            # AUTHENTICATED mode can verify nothing, so it rejects everything.
            return _EnvelopeVerdict(
                False, advisory=False,
                reason="cryptography is unavailable in authenticated mode; "
                "rejecting (fail closed)",
            )
        if errors:
            return _EnvelopeVerdict(False, advisory=False, reason="; ".join(errors))

        expires_at = _parse_datetime(wire.get("expires_at"))
        if expires_at is None:
            return _EnvelopeVerdict(
                False, advisory=False,
                reason="expires_at is missing or not a parseable date-time",
            )
        if expires_at <= datetime.now(timezone.utc):
            return _EnvelopeVerdict(False, advisory=False, reason="envelope has expired")

        nonce = wire.get("nonce")
        if not nonce:
            return _EnvelopeVerdict(False, advisory=False, reason="missing nonce")
        # FIX 2(c): `__post_init__` guarantees `nonce_store` is never None
        # here (AUTHENTICATED mode always has one -- an explicit injection or
        # the durable `FileNonceStore` default); this replay check is never
        # conditionally skipped. The `is not None` guard stays as an explicit
        # fail-closed belt: if some future caller ever bypasses `__post_init__`
        # by mutating `nonce_store` back to `None`, missing the check would be
        # a silent skip, so reject instead.
        if self.nonce_store is None:
            return _EnvelopeVerdict(
                False, advisory=False,
                reason="authenticated mode requires a nonce store for replay "
                "checking; none is configured (fail closed)",
            )
        if self.nonce_store.seen(msg.from_.actor, nonce):
            return _EnvelopeVerdict(
                False, advisory=False,
                reason="nonce replay: this (sender, nonce) was already honoured",
            )

        auth = authorize(
            from_role=msg.from_.role, verb=msg.verb,
            maker_id=self.session_id, roster=self.roster,
        )
        if not auth.allowed:
            return _EnvelopeVerdict(False, advisory=False, reason=auth.reason)

        if self.nonce_store is not None:
            # Record only once every other check has passed, so a forged or
            # garbage envelope can never burn a legitimate sender's nonce.
            self.nonce_store.record(msg.from_.actor, nonce)

        return _EnvelopeVerdict(True, advisory=False, reason="authenticated")

    def _reject(self, msg: Message, reason: str) -> Message:
        return env.new_message(
            from_=self._me(),
            to=self._to_compliance(msg),
            verb=Verb.ACK,
            body=env.ack_body(directive_ref=msg.id, accepted=False, note=reason),
            authority=self._maker_authority(msg),
            correlates=msg.id,
        )

    # --- envelope helpers ----------------------------------------------------

    def _me(self) -> Party:
        return Party(actor=self.session_id, role=self.role)

    def _to_compliance(self, msg: Message) -> Party:
        return Party(actor=self.compliance_actor, role=msg.from_.role)

    def _maker_authority(self, msg: Message) -> Authority:
        # A maker->compliance reply carries a role-basis authority naming itself.
        return Authority(basis="role", role=self.role, oversees=None, reserved=False)

    # --- Protocol handlers (SPEC §9) -----------------------------------------

    def accept_directive(self, msg: Message) -> Message:
        """Honour issue-directive / hold / resume. Returns an `ack`."""
        verb = msg.verb
        if verb is Verb.ISSUE_DIRECTIVE:
            rec = DirectiveRecord(
                directive_id=msg.id,
                kind=msg.body.get("kind", ""),
                instruction=msg.body.get("instruction", ""),
            )
            self.directives.append(rec)
            note = f"applied directive kind={rec.kind!r}"
            accepted = True
        elif verb is Verb.HOLD:
            self._held = True
            self._hold_ref = msg.id
            self._hold_conditions = list(msg.body.get("conditions", []) or [])
            note = "held at next checkpoint (cooperative)"
            accepted = True
        elif verb is Verb.RESUME:
            self._held = False
            self._hold_ref = None
            self._hold_conditions = []
            note = "resumed"
            accepted = True
        else:
            note = f"{verb.value} is not an accept-directive verb"
            accepted = False

        return env.new_message(
            from_=self._me(),
            to=self._to_compliance(msg),
            verb=Verb.ACK,
            body=env.ack_body(directive_ref=msg.id, accepted=accepted, note=note),
            authority=self._maker_authority(msg),
            correlates=msg.id,
        )

    def report_state(self, query: Message) -> Message:
        """Answer a query-state, stamped provenance='self-report' (never
        promoted to witnessed/observed)."""
        include = list(query.body.get("include", []))
        state = self.state_provider(include) if self.state_provider else {}
        body = env.report_state_body(
            mandate=state.get("mandate"),
            trajectory=state.get("trajectory"),
            tools=state.get("tools"),
            claims=state.get("claims"),
        )
        return env.new_message(
            from_=self._me(),
            to=self._to_compliance(query),
            verb=Verb.REPORT_STATE,
            body=body,
            authority=self._maker_authority(query),
            correlates=query.id,
        )

    def halt(self, msg: Message) -> Message:
        """Honour a halt: set the cooperative-stop signal and ack. This is NOT a
        forced kill — it takes effect when the maker's loop next consults
        `should_continue()`."""
        self._halted = True
        return env.new_message(
            from_=self._me(),
            to=self._to_compliance(msg),
            verb=Verb.ACK,
            body=env.ack_body(
                directive_ref=msg.id,
                accepted=True,
                note="halt honoured cooperatively; stopping at next checkpoint "
                "(not a forced kill)",
            ),
            authority=self._maker_authority(msg),
            correlates=msg.id,
        )

    # --- the poll checkpoint -------------------------------------------------

    def checkpoint(self) -> list[Message]:
        """Drain the inbox, honour each pending directive in order, and post the
        response back to the compliance actor. Returns the response messages.

        A maker calls this at its turn boundaries. `hold`/`halt` mutate the
        cooperative-stop signals the maker's loop consults.

        Every envelope is verified (`_verify_envelope`) BEFORE it is applied.
        In AUTHENTICATED mode (a trust store is configured) a message that
        fails signature, expiry, replay or authority checks is NEVER applied
        — it is rejected: reported back as `ack{accepted: False}` with a
        reason, and the maker's own state is left untouched. In BARE/ADVISORY
        mode every message is applied, but the response is labelled
        `mode: "advisory"` so a caller can never mistake it for a verified
        directive."""
        responses: list[Message] = []
        for wire in self.inbox.poll(self.session_id):
            msg = env.from_wire(wire)
            verdict = self._verify_envelope(wire, msg)
            if not verdict.ok:
                resp = self._reject(msg, verdict.reason)
            elif msg.verb is Verb.QUERY_STATE:
                resp = self.report_state(msg)
            elif msg.verb is Verb.HALT:
                resp = self.halt(msg)
            elif msg.verb in (Verb.ISSUE_DIRECTIVE, Verb.HOLD, Verb.RESUME):
                resp = self.accept_directive(msg)
            else:
                # Unknown / maker->compliance verb arriving here: ignore, no reply.
                continue
            if verdict.ok:
                resp.body["mode"] = "advisory" if verdict.advisory else "authenticated"
            self.inbox.put(self.compliance_actor, env.to_wire(resp))
            responses.append(resp)
        return responses
