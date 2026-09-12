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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from interfaces.a2a_control import Verb, Party, Authority, Message
from . import envelope as env
from .inbox import FileInbox


StateProvider = Callable[[list[str]], dict]


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

    _halted: bool = field(default=False, init=False)
    _held: bool = field(default=False, init=False)
    _hold_ref: Optional[str] = field(default=None, init=False)
    _hold_conditions: list[str] = field(default_factory=list, init=False)
    directives: list[DirectiveRecord] = field(default_factory=list, init=False)

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
        cooperative-stop signals the maker's loop consults."""
        responses: list[Message] = []
        for wire in self.inbox.poll(self.session_id):
            msg = env.from_wire(wire)
            if msg.verb is Verb.QUERY_STATE:
                resp = self.report_state(msg)
            elif msg.verb is Verb.HALT:
                resp = self.halt(msg)
            elif msg.verb in (Verb.ISSUE_DIRECTIVE, Verb.HOLD, Verb.RESUME):
                resp = self.accept_directive(msg)
            else:
                # Unknown / maker->compliance verb arriving here: ignore, no reply.
                continue
            self.inbox.put(self.compliance_actor, env.to_wire(resp))
            responses.append(resp)
        return responses
