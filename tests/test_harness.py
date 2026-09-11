"""Harness transport (SPEC §9 option 3, §11 gap 1): enforceable send/stop for a
spawn-owned maker via the subprocess driver, the participant/transport contract
it satisfies, the cooperative fallback for a maker it did NOT spawn, and the
no-hard-import-on-the-default-path guard.

These run a REAL child process (the dummy maker) — send is over the shared file
inbox the maker drains at its checkpoints; stop is a real process termination.
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest

from a2a_compliance import (
    ComplianceAgent, ControlParticipant, FileInbox, Roster, Verb,
)
from a2a_compliance import envelope as env
from a2a_compliance.harness import (
    HarnessTransport,
    SubprocessSpawner,
    ClaudeHarnessSpawner,
    MakerSpec,
    DirectiveTransport,
)
from interfaces.a2a_control import Party, Authority

ROOT = Path(__file__).resolve().parent.parent
DUMMY = ROOT / "tests" / "fixtures" / "dummy_maker.py"


def _wait_until(pred, timeout=6.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return False


@pytest.fixture
def transport(tmp_path):
    t = HarnessTransport(
        inbox_root=tmp_path / "a2a", spawner=SubprocessSpawner(),
        compliance_actor="comp-1",
    )
    yield t
    # tear down any still-live spawned makers
    for sid in list(t._handles):
        t.stop(sid)


def _spawn(transport, session_id="maker-live", heartbeat=None):
    spec = MakerSpec(
        session_id=session_id,
        argv=[sys.executable, str(DUMMY)],
        compliance_actor="comp-1",
        env={"A2A_HEARTBEAT": str(heartbeat)} if heartbeat else None,
    )
    return transport.spawn(spec)


# --- the transport satisfies the shared put/poll seam ----------------------

def test_harness_transport_is_a_directive_transport(transport):
    # HarnessTransport is a drop-in for the same seam FileInbox satisfies, so a
    # ComplianceAgent / ControlParticipant accepts it as `inbox=` unchanged.
    assert isinstance(transport, DirectiveTransport)
    comp = ComplianceAgent("comp-1", "policy-compliance", transport, Roster())
    res = comp.query_state("some-maker", ["mandate"])
    assert res.dispatched  # went through transport.put without any caller change


# --- spawn-owned maker: REAL enforceable send + stop -----------------------

def test_spawn_deliver_ack_then_hard_stop(transport, tmp_path):
    hb = tmp_path / "beat"
    handle = _spawn(transport, "maker-live", heartbeat=hb)

    # the child is genuinely running
    assert _wait_until(lambda: handle.is_alive() and hb.exists())
    assert transport.owns("maker-live")

    # deliver a directive via the OWNED handle (enforceable send over the inbox)
    comp = ComplianceAgent("comp-1", "policy-compliance", transport, Roster())
    directive = comp.issue_directive("maker-live", "narrow scope", "constrain")
    assert directive.dispatched

    # the maker drains it at a checkpoint and acks back to the compliance actor
    inbox = FileInbox(tmp_path / "a2a")
    got = {}

    def _acked():
        for w in inbox.poll("comp-1"):
            if w["verb"] == Verb.ACK.value:
                got["ack"] = w
                return True
        return False

    assert _wait_until(_acked), "maker did not ack the delivered directive"
    assert got["ack"]["body"]["accepted"] is True
    assert got["ack"]["correlates"] == directive.message.id  # same-contract round-trip

    # stop() is a REAL termination — assert the process is actually gone
    pid = handle.pid
    result = transport.stop("maker-live")
    assert result.enforceable is True
    assert result.mechanism == "process-terminate"
    assert result.terminated is True
    assert handle.is_alive() is False
    assert not _process_alive(pid)
    assert transport.owns("maker-live") is False


def _process_alive(pid: int) -> bool:
    import os
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_query_state_roundtrip_over_owned_handle(transport, tmp_path):
    handle = _spawn(transport, "maker-q")
    assert _wait_until(handle.is_alive)

    handle.deliver(_query("comp-1", "maker-q", ["mandate"]))
    inbox = FileInbox(tmp_path / "a2a")
    got = {}

    def _reported():
        for w in inbox.poll("comp-1"):
            if w["verb"] == Verb.REPORT_STATE.value:
                got["r"] = w
                return True
        return False

    assert _wait_until(_reported)
    assert got["r"]["body"]["provenance"] == "self-report"  # never promoted
    transport.stop("maker-q")


def _query(from_actor, to_actor, include):
    return env.new_message(
        from_=Party(actor=from_actor, role="policy-compliance"),
        to=Party(actor=to_actor, role="maker"),
        verb=Verb.QUERY_STATE,
        body=env.query_state_body(include),
        authority=Authority(basis="role", role="policy-compliance",
                            oversees=to_actor, reserved=False),
    )


# --- maker NOT spawned by this transport: cooperative fallback -------------

def test_non_owned_maker_degrades_to_cooperative_halt(transport, tmp_path):
    # No spawn — this maker is an ordinary in-process cooperative-poll participant.
    inbox = FileInbox(tmp_path / "a2a")
    maker = ControlParticipant(
        session_id="maker-coop", inbox=inbox, compliance_actor="comp-1",
        state_provider=lambda inc: {},
    )
    assert transport.owns("maker-coop") is False

    # a prebuilt halt (built via the reserved-act-gated ComplianceAgent path)
    comp = ComplianceAgent("comp-1", "policy-compliance", transport, Roster())
    approved = comp.halt("maker-coop", reason_ref="off-mandate", confirm=True)
    assert approved.dispatched  # ComplianceAgent already delivered it via transport.put

    # stop() with no owned handle is honest: cooperative, not a forced kill
    result = transport.stop("maker-coop", cooperative_halt=approved.message)
    assert result.enforceable is False
    assert result.mechanism == "cooperative-halt"
    assert result.terminated is False

    # the maker honours the halt at its next checkpoint (cooperative stop)
    maker.checkpoint()
    assert maker.should_continue() is False


def test_deliver_to_non_owned_uses_inbox(transport, tmp_path):
    inbox = FileInbox(tmp_path / "a2a")
    maker = ControlParticipant(
        session_id="maker-coop2", inbox=inbox, compliance_actor="comp-1",
        state_provider=lambda inc: {},
    )
    transport.deliver("maker-coop2", _query("comp-1", "maker-coop2", ["mandate"]))
    resp = maker.checkpoint()
    assert resp and resp[0].verb is Verb.REPORT_STATE


# --- Claude-Code binding is a seam, not a working driver -------------------

def test_claude_spawner_is_an_unwired_seam():
    spawner = ClaudeHarnessSpawner()  # no injected host callables
    with pytest.raises(NotImplementedError):
        spawner.spawn(MakerSpec(session_id="x", argv=[], inbox_root="/tmp"))


def test_claude_spawner_uses_injected_spawn_fn():
    calls = {}

    def fake_spawn(spec):
        calls["spec"] = spec
        return "handle-sentinel"

    spawner = ClaudeHarnessSpawner(spawn_fn=fake_spawn)
    out = spawner.spawn(MakerSpec(session_id="x", argv=[], inbox_root="/tmp"))
    assert out == "handle-sentinel"
    assert calls["spec"].session_id == "x"


# --- guard: the harness is NOT on the default import path ------------------

def test_harness_not_imported_on_bare_package_import():
    code = (
        "import sys; import a2a_compliance; "
        "mods = [m for m in sys.modules if m.startswith('a2a_compliance.harness')]; "
        "assert mods == [], mods; "
        "print('OK')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], cwd=str(ROOT),
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
