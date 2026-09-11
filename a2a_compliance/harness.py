"""Live send/stop transport for spawn-owned makers (SPEC §9 option 3, §11 gap 1).

The enforceable counterpart to the cooperative-poll `FileInbox`
(`inbox.py` / `participant.py`). It is an OPTIONAL, opt-in harness transport
behind the SAME participant/transport contract Phase 1 defines
(`query-state` / `issue-directive` / `hold` / `resume` / `halt`): it delivers
the identical control-message envelopes and adds a REAL stop for a maker THIS
transport owns.

NOT on the default import path. `import a2a_compliance` does not pull this in;
callers opt in with `from a2a_compliance import harness` (or
`from a2a_compliance.harness import HarnessTransport, SubprocessSpawner`). The
cooperative-poll transport stays the default (SPEC invariant: optional +
import-guarded); no `loomground_*` / `rvnd.*` import is on any path here.

Two honest tiers (SPEC §9):

- **Spawn-owned maker** — a maker this transport launched. `deliver()` sends a
  directive over the existing file-inbox channel the maker drains at its
  checkpoints; `stop()` is a REAL termination of the child process. Genuinely
  enforceable send/stop.
- **Maker this transport did NOT spawn** — cooperative fallback. `deliver()` and
  `stop()` delegate to the plain `FileInbox`: the maker observes the directive /
  `halt` at its next checkpoint. The harness does NOT expose arbitrary live
  cross-session messaging, so it cannot forcibly halt a live peer it did not
  spawn — that stays a cooperative stop, and this module says so rather than
  pretending otherwise.

The `Spawner` Protocol is the driver SEAM. `SubprocessSpawner` is the real,
testable default (a maker runs as a child process). `ClaudeHarnessSpawner` is a
documented injection point for the Claude-Code harness (spawn ~ the Agent tool,
stop ~ TaskStop) — those are host agent-tools, not a Python API, so it is a seam
the host wires, NOT a working driver in this module.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from interfaces.a2a_control import Message
from . import envelope as env
from .inbox import FileInbox


# --- the minimal shared transport seam ------------------------------------
# Phase 1 already relies on exactly this send/receive surface: a compliance
# agent `put`s a control message addressed to an actor, and that actor `poll`s
# its own mailbox at a checkpoint. `FileInbox` satisfies it structurally, and so
# does `HarnessTransport` (below) by delegating to a FileInbox — which is why a
# `ComplianceAgent(inbox=harness_transport)` or `ControlParticipant(inbox=...)`
# works unchanged. Introduced minimally here (not on the default import path) so
# both the cooperative-poll transport and this one share one interface.

@runtime_checkable
class DirectiveTransport(Protocol):
    """The put/poll seam both transports satisfy (SPEC §3 channel)."""

    def put(self, to_actor: str, msg_wire: dict) -> int: ...
    def poll(self, actor: str) -> list[dict]: ...


# --- the driver seam -------------------------------------------------------

@dataclass
class MakerSpec:
    """What a `Spawner` needs to launch a maker as a process it owns.

    `session_id` is the maker's A2A actor id (its inbox key). `argv` is the
    command that launches the maker; the launched maker MUST build a
    `ControlParticipant` bound to a `FileInbox` at `inbox_root` and drain it at
    its checkpoints. `inbox_root` is filled in by `HarnessTransport.spawn` when
    left None so the maker and the transport share one inbox root."""

    session_id: str
    argv: list[str]
    compliance_actor: str = "compliance"
    inbox_root: Optional[str] = None
    cwd: Optional[str] = None
    env: Optional[dict] = None


@runtime_checkable
class MakerHandle(Protocol):
    """A handle to a maker the transport OWNS.

    `deliver(msg)` sends a control message the maker drains at its next
    checkpoint (real send over the file-inbox channel). `stop()` is a REAL
    termination, not a polite request. `is_alive()` reports liveness."""

    session_id: str

    def deliver(self, msg: Message) -> None: ...
    def stop(self, *, timeout: float = 5.0) -> bool: ...
    def is_alive(self) -> bool: ...


@runtime_checkable
class Spawner(Protocol):
    """The driver SEAM. Launches a maker and returns a `MakerHandle` that can
    deliver directives to it and stop it.

    `SubprocessSpawner` is the real default. The Claude-Code harness binding is a
    separate, documented `Spawner` implementation (`ClaudeHarnessSpawner`) that
    the HOST wires — spawn ~ the Agent tool, stop ~ TaskStop — because those are
    host agent-tools, not a Python API."""

    def spawn(self, spec: MakerSpec) -> MakerHandle: ...


# --- real default driver: subprocess --------------------------------------

@dataclass
class SubprocessMakerHandle:
    """Handle to a maker running as a child process this transport owns.

    Send is real (over the shared file-inbox channel the maker drains at its
    checkpoints); stop is real (process termination)."""

    session_id: str
    _proc: subprocess.Popen
    _inbox: FileInbox
    compliance_actor: str = "compliance"

    def deliver(self, msg: Message) -> None:
        """Send a control message to the owned maker. It is drained at the
        maker's next checkpoint — same channel, same envelope as Phase 1."""
        self._inbox.put(self.session_id, env.to_wire(msg))

    def is_alive(self) -> bool:
        return self._proc.poll() is None

    def stop(self, *, timeout: float = 5.0) -> bool:
        """Terminate the child process. Real, enforceable stop: SIGTERM, then
        SIGKILL if it does not exit within `timeout`. Returns True once the
        process is gone."""
        if self._proc.poll() is not None:
            return True
        self._proc.terminate()
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return False
        return self._proc.poll() is not None

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def returncode(self) -> Optional[int]:
        return self._proc.poll()


class SubprocessSpawner:
    """Real, testable `Spawner` default: launches a maker as a child process and
    delivers directives to it over the existing file-inbox channel.

    No harness/host dependency — `subprocess` (stdlib) is only loaded because
    this opt-in module was imported. The launched maker is any program that
    drains a `FileInbox` at its checkpoints (see the dummy maker used in the
    test suite for a minimal, real example)."""

    def spawn(self, spec: MakerSpec) -> SubprocessMakerHandle:
        if spec.inbox_root is None:
            raise ValueError(
                "MakerSpec.inbox_root is required to spawn — the maker and the "
                "transport must share one inbox root (HarnessTransport.spawn "
                "fills it in when omitted)."
            )
        child_env = dict(os.environ)
        if spec.env:
            child_env.update({k: str(v) for k, v in spec.env.items()})
        # Pass the A2A wiring to the maker via the environment (the maker reads
        # these to build its ControlParticipant).
        child_env.setdefault("A2A_INBOX_ROOT", str(spec.inbox_root))
        child_env.setdefault("A2A_SESSION_ID", spec.session_id)
        child_env.setdefault("A2A_COMPLIANCE_ACTOR", spec.compliance_actor)
        proc = subprocess.Popen(
            spec.argv,
            cwd=spec.cwd,
            env=child_env,
            stdin=subprocess.DEVNULL,
        )
        return SubprocessMakerHandle(
            session_id=spec.session_id,
            _proc=proc,
            _inbox=FileInbox(spec.inbox_root),
            compliance_actor=spec.compliance_actor,
        )


# --- the Claude-Code harness binding: a documented seam, NOT a driver ------

class ClaudeHarnessSpawner:
    """Injection point for the Claude-Code harness — a documented SEAM, not a
    working driver.

    On the Claude-Code host, spawn/stop are host AGENT-TOOLS, not a Python API:

      - **spawn** ~ the **Agent** tool (launch a subagent / maker session), and
      - **stop**  ~ **TaskStop** (stop a running background agent by id).

    Those tools are invoked by the host model, not callable from inside this
    process, so this class deliberately does NOT implement them. To wire the
    Claude harness, inject callables that perform the host tool-calls:

        spawner = ClaudeHarnessSpawner(
            spawn_fn=lambda spec: <host: Agent(...) -> agent_id>,
            stop_fn=lambda agent_id: <host: TaskStop(agent_id)>,
            deliver_fn=lambda agent_id, msg: <host: SendMessage(agent_id, ...)>,
        )

    Absent that wiring, `spawn()` raises to keep the seam honest — an
    unimplemented harness must fail loudly, never silently pretend to own a
    live session. Even wired, `deliver` to a live session is bounded by what the
    host exposes: the harness does not generally expose arbitrary live
    cross-session messaging, so mid-run delivery may still degrade to the
    cooperative file-inbox checkpoint (SPEC §9)."""

    def __init__(self, *, spawn_fn=None, stop_fn=None, deliver_fn=None):
        self._spawn_fn = spawn_fn
        self._stop_fn = stop_fn
        self._deliver_fn = deliver_fn

    def spawn(self, spec: MakerSpec) -> MakerHandle:
        if self._spawn_fn is None:
            raise NotImplementedError(
                "ClaudeHarnessSpawner is a seam: inject spawn_fn/stop_fn/"
                "deliver_fn that call the host Agent / TaskStop / SendMessage "
                "tools. It is intentionally not a working in-module driver."
            )
        return self._spawn_fn(spec)  # pragma: no cover — host-wired path


# --- the transport: owned enforceable send/stop + cooperative fallback -----

@dataclass
class StopResult:
    """Outcome of a `HarnessTransport.stop`. `enforceable` is True only for a
    real process termination of an owned maker; a non-owned maker degrades to a
    cooperative `halt` delivered over the file inbox, `terminated=False` (it
    takes effect at the maker's next checkpoint)."""

    enforceable: bool
    mechanism: str  # "process-terminate" | "cooperative-halt"
    terminated: bool
    note: str


@dataclass
class HarnessTransport:
    """Optional, opt-in send/stop transport for makers the fleet SPAWNS.

    Satisfies the same put/poll transport seam as `FileInbox` (it delegates to an
    internal one), so it is a drop-in for `ComplianceAgent(inbox=...)` and
    `ControlParticipant(inbox=...)` — the harness binds real send/stop WITHOUT
    changing those callers. On top of put/poll it adds `spawn`/`deliver`/`stop`:

      - a maker it spawned  -> enforceable send (`deliver`) + real stop (`stop`);
      - a maker it did not  -> cooperative fallback over the file inbox.
    """

    inbox_root: str | Path
    spawner: Spawner
    compliance_actor: str = "compliance"
    _handles: dict[str, MakerHandle] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._inbox = FileInbox(self.inbox_root)

    # -- the shared transport seam (drop-in for FileInbox) ------------------

    def put(self, to_actor: str, msg_wire: dict) -> int:
        return self._inbox.put(to_actor, msg_wire)

    def poll(self, actor: str) -> list[dict]:
        return self._inbox.poll(actor)

    def peek(self, actor: str) -> list[dict]:
        return self._inbox.peek(actor)

    # -- lifecycle ----------------------------------------------------------

    def spawn(self, spec: MakerSpec) -> MakerHandle:
        """Spawn a maker this transport OWNS and record its handle."""
        if spec.inbox_root is None:
            spec.inbox_root = str(self.inbox_root)
        if not spec.compliance_actor:
            spec.compliance_actor = self.compliance_actor
        handle = self.spawner.spawn(spec)
        self._handles[spec.session_id] = handle
        return handle

    def owns(self, session_id: str) -> bool:
        """True iff this transport spawned `session_id` and it is still live."""
        h = self._handles.get(session_id)
        return h is not None and h.is_alive()

    def handle(self, session_id: str) -> Optional[MakerHandle]:
        return self._handles.get(session_id)

    # -- send ---------------------------------------------------------------

    def deliver(self, to_actor: str, msg: Message) -> None:
        """Send a control message. Enforceable for an owned maker (via its
        handle); cooperative for others (plain file-inbox put — drained at the
        maker's next checkpoint). The envelope is identical either way."""
        h = self._handles.get(to_actor)
        if h is not None and h.is_alive():
            h.deliver(msg)
        else:
            self._inbox.put(to_actor, env.to_wire(msg))

    # -- stop ---------------------------------------------------------------

    def stop(
        self,
        session_id: str,
        *,
        cooperative_halt: Optional[Message] = None,
        timeout: float = 5.0,
    ) -> StopResult:
        """Stop a maker.

        Owned + live -> REAL termination of the child process (enforceable).
        Otherwise -> cooperative fallback: if a prebuilt `halt` message is given
        it is delivered over the file inbox (honoured at the maker's next
        checkpoint); the harness does NOT claim a forced kill of a maker it does
        not own."""
        h = self._handles.get(session_id)
        if h is not None and h.is_alive():
            terminated = h.stop(timeout=timeout)
            return StopResult(
                enforceable=True,
                mechanism="process-terminate",
                terminated=terminated,
                note="owned maker: child process terminated",
            )
        # Non-owned (or already-dead) maker: cooperative fallback only.
        if cooperative_halt is not None:
            self._inbox.put(session_id, env.to_wire(cooperative_halt))
            note = (
                "not owned by this transport: cooperative halt delivered over "
                "the file inbox; takes effect at the maker's next checkpoint "
                "(not a forced kill)"
            )
        else:
            note = (
                "not owned by this transport and no cooperative halt provided; "
                "the harness cannot force-stop a maker it did not spawn"
            )
        return StopResult(
            enforceable=False,
            mechanism="cooperative-halt",
            terminated=False,
            note=note,
        )
