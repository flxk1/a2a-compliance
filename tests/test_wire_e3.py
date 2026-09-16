"""E3 conformance suite: mediated executor (`a2a_compliance.wire.executor`).

Builds a real, signed, schema-valid `ExecutionPermit` directly from an
`AdmissionResult` (E2's `issue_permit`) -- same TEST-ONLY dev signer over an
ephemeral dev keypair as every other suite here, never a production key.
`FakeExecutor` stands in for a host's real `ExecutorPort`: it is the ONLY
thing in this file that would be replaced by a real effect (see
`examples/subprocess_adapter.py` / `tests/test_e3_subprocess_adapter.py` for
the real-subprocess conformance proof); this file exercises the mediation
protocol itself -- verify -> match -> atomic-consume -> execute -> receipt.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import AdmissionDecision, AdmissionResult, dev_issuer, issue_permit
from a2a_compliance.wire.executor import (
    ExecutionOutcome,
    bind_constraints,
    consume_and_execute,
)
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryRevocationStore, InMemoryTrustStore
from a2a_compliance.wire.verification import InMemoryNonceStore, verify

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
FAR_FUTURE = NOW + timedelta(hours=1)


class FakeExecutor:
    """Test double for `wire.executor.ExecutorPort`. Records every call it
    actually receives so tests can assert a rejected attempt never reached
    it -- the same shape of proof `examples/subprocess_adapter.py` gives
    with a real subprocess."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome:
        self.calls.append((tool, dict(arguments)))
        return ExecutionOutcome(
            effect={"ok": True, "echoed": arguments},
            executor_id="fake:executor-1", executor_role="tool-executor",
        )


@pytest.fixture()
def keys():
    return {
        "issuer": generate_dev_keypair(),
        "recorder": generate_dev_keypair(),
        "forger": generate_dev_keypair(),
    }


def _trust_store(keys) -> InMemoryTrustStore:
    store = InMemoryTrustStore()
    store.add("key-issuer", keys["issuer"][1], frozenset({"ExecutionPermit"}), frozenset())
    store.add("key-recorder", keys["recorder"][1], frozenset({"ToolReceipt"}), frozenset())
    # key-forger is deliberately NOT registered under its own key_id.
    return store


def _admitted(action_digest: str) -> AdmissionResult:
    return AdmissionResult(AdmissionDecision.ADMITTED, action_digest, "edit")


def _permit(
    keys, tool, arguments, *, nonce_store, run_id="run-e3-0001", nonce="permit-nonce-1",
    grade="mediated", expires_at=FAR_FUTURE, action_digest=None, extra_constraints=None,
):
    action_digest = action_digest or canonical.digest_hex({"kind": "edit", "run": run_id})
    admission = _admitted(action_digest)
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade=grade, adapter="subprocess",
        run_id=run_id, nonce=nonce, expires_at=expires_at, nonce_store=nonce_store,
        constraints=bind_constraints(tool, arguments, extra=extra_constraints), issued_at=NOW,
    )
    assert result.ok, result.reasons
    return result.permit


def _signer(keys):
    return dev_issuer("key-recorder", "recorder:enforcement", keys["recorder"][0])


# --- positive: valid permit -> exactly one execution -> one verifiable
# receipt; the nonce is then consumed so a replay/reuse fails -------------

def test_valid_permit_executes_once_and_produces_a_verifiable_receipt(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "ops@example.com", "body": "hello"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="dispatch-1", now=NOW,
    )
    assert result.ok, result.reasons
    assert executor.calls == [(tool, arguments)]

    receipt = result.receipt
    assert receipt["type"] == "ToolReceipt"
    assert receipt["tool"] == tool
    assert receipt["action_digest"] == permit["action_digest"]
    assert receipt["arguments_digest"] == canonical.digest_hex(arguments)
    assert receipt["effect_digest"] == canonical.digest_hex({"ok": True, "echoed": arguments})
    assert receipt["executor"] == {"id": "fake:executor-1", "role": "tool-executor"}

    verified = verify(receipt, "ToolReceipt", trust_store=trust_store, now=NOW)
    assert verified.ok, verified.errors

    # reuse: the SAME permit cannot dispatch a second time.
    replay = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="dispatch-2", now=NOW,
    )
    assert replay.ok is False
    assert any("already consumed" in r for r in replay.reasons)
    assert executor.calls == [(tool, arguments)], "no second real effect on replay"


# --- bypass: no path to the tool except a valid permit --------------------

def test_bypass_no_permit_produces_no_effect(keys):
    executor = FakeExecutor()
    result = consume_and_execute(
        None, tool="send-email", arguments={"to": "x"},
        trust_store=_trust_store(keys), nonce_store=InMemoryNonceStore(),
        executor=executor, signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert result.receipt is None
    assert executor.calls == []


def test_bypass_invalid_signature_permit_produces_no_effect(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "x"}
    permit = dict(_permit(keys, tool, arguments, nonce_store=nonce_store))
    permit["adapter"] = "tampered-after-signing"  # subject changes, signature stays stale

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert any("subject_digest mismatch" in r for r in result.reasons)
    assert executor.calls == []


def test_bypass_wrong_key_signed_permit_produces_no_effect(keys):
    # Claims key_id "key-issuer" (registered, authorized for ExecutionPermit)
    # but is actually signed by an unrelated, unregistered private key.
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "x"}
    permit = dict(_permit(keys, tool, arguments, nonce_store=nonce_store))
    permit["signature"] = dev_sign_subject(permit, keys["forger"][0])

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert any("Ed25519 signature does not verify" in r for r in result.reasons)
    assert executor.calls == []


def test_advisory_grade_permit_does_not_authorize_execution(keys):
    # Only mediated/platform are enforcement grades (plan: 'Outcome');
    # an advisory-grade permit -- even if validly signed -- must not
    # authorize a real effect through this mediated path.
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "x"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store, grade="advisory")

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert any("does not authorize mediated execution" in r for r in result.reasons)
    assert executor.calls == []


# --- reuse: atomic nonce consumption -- a second consumption fails --------

def test_reuse_is_rejected_even_with_a_brand_new_executor_instance(keys):
    # Reuse is about the (run_id, nonce) pair, not about calling through
    # the same executor object twice.
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "x"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)

    first = consume_and_execute(
        permit, tool=tool, arguments=arguments, trust_store=trust_store,
        nonce_store=nonce_store, executor=FakeExecutor(), signer=_signer(keys),
        dispatch_id="d1", now=NOW,
    )
    assert first.ok

    second_executor = FakeExecutor()
    second = consume_and_execute(
        permit, tool=tool, arguments=arguments, trust_store=trust_store,
        nonce_store=nonce_store, executor=second_executor, signer=_signer(keys),
        dispatch_id="d2", now=NOW,
    )
    assert second.ok is False
    assert any("already consumed" in r for r in second.reasons)
    assert second_executor.calls == []


def test_nonce_store_consume_is_compare_and_set():
    from a2a_compliance.wire.verification import InMemoryNonceStore as NS

    store = NS()
    assert store.consume("run-1", "nonce-1") is True
    assert store.consume("run-1", "nonce-1") is False
    assert store.consume("run-1", "nonce-1") is False
    # a different (run_id, nonce) pair is independent.
    assert store.consume("run-1", "nonce-2") is True
    assert store.consume("run-2", "nonce-1") is True
    # consume() and seen()/record() track independent state (E3 vs E1/E2).
    assert store.seen("run-1", "nonce-1") is False
    store.record("run-1", "nonce-1")
    assert store.seen("run-1", "nonce-1") is True


# --- drift: valid at admission, stale/revoked as of execution time --------

def test_drift_expired_permit_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "x"}
    permit = _permit(
        keys, tool, arguments, nonce_store=nonce_store,
        expires_at=NOW + timedelta(minutes=5),
    )
    later = NOW + timedelta(hours=2)  # past the permit's expiry

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=later,
    )
    assert result.ok is False
    assert any("stale" in r for r in result.reasons)
    assert executor.calls == []


def test_drift_revoked_key_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    revocation_store = InMemoryRevocationStore()
    tool, arguments = "send-email", {"to": "x"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    revocation_store.revoke("key", "key-issuer", NOW - timedelta(minutes=1))

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", revocation_store=revocation_store, now=NOW,
    )
    assert result.ok is False
    assert any("revoked: key_id" in r for r in result.reasons)
    assert executor.calls == []


def test_drift_revoked_run_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    revocation_store = InMemoryRevocationStore()
    tool, arguments = "send-email", {"to": "x"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store, run_id="run-e3-drift")
    revocation_store.revoke("run", "run-e3-drift", NOW - timedelta(minutes=1))

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", revocation_store=revocation_store, now=NOW,
    )
    assert result.ok is False
    assert any("revoked: run_id" in r for r in result.reasons)
    assert executor.calls == []


def test_drift_revoked_permit_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    revocation_store = InMemoryRevocationStore()
    tool, arguments = "send-email", {"to": "x"}
    digest = canonical.digest_hex({"kind": "edit", "revoke-me": True})
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store, action_digest=digest)
    revocation_store.revoke("permit", digest, NOW - timedelta(minutes=1))

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", revocation_store=revocation_store, now=NOW,
    )
    assert result.ok is False
    assert any("revoked: permit" in r for r in result.reasons)
    assert executor.calls == []


# --- argument mutation: executed call must equal the permitted one --------

def test_argument_mutation_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool = "send-email"
    permit = _permit(keys, tool, {"to": "ops@example.com"}, nonce_store=nonce_store)

    result = consume_and_execute(
        permit, tool=tool, arguments={"to": "attacker@example.com"},
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert any("argument mutation" in r for r in result.reasons)
    assert executor.calls == []


def test_tool_substitution_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    arguments = {"to": "ops@example.com"}
    permit = _permit(keys, "send-email", arguments, nonce_store=nonce_store)

    result = consume_and_execute(
        permit, tool="delete-inbox", arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert any("tool mismatch" in r for r in result.reasons)
    assert executor.calls == []


def test_permit_with_no_constraints_binding_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    admission = _admitted(canonical.digest_hex({"kind": "edit"}))
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    issued = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-e3-unbound", nonce="n1", expires_at=FAR_FUTURE, nonce_store=nonce_store,
    )
    assert issued.ok, issued.reasons

    result = consume_and_execute(
        issued.permit, tool="send-email", arguments={"to": "x"},
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert any("do not bind a tool/arguments_digest" in r for r in result.reasons)
    assert executor.calls == []


# --- bind_constraints helper -----------------------------------------------

def test_bind_constraints_rejects_reserved_keys_in_extra():
    with pytest.raises(ValueError):
        bind_constraints("send-email", {"to": "x"}, extra={"tool": "clobber"})


def test_bind_constraints_merges_extra():
    bound = bind_constraints("send-email", {"to": "x"}, extra={"lane": "prod"})
    assert bound["tool"] == "send-email"
    assert bound["lane"] == "prod"
    assert bound["arguments_digest"] == canonical.digest_hex({"to": "x"})


# --- bare-install / lazy-reachability --------------------------------------

def test_executor_symbols_are_reachable_only_via_lazy_wire_getattr():
    from a2a_compliance import wire

    assert wire.consume_and_execute is consume_and_execute
    assert wire.bind_constraints is bind_constraints


# --- fixed trust boundary: core performs no host effect --------------------

_FORBIDDEN_TOKENS = (
    "import subprocess", "subprocess.run(", "subprocess.Popen(", "subprocess.call(",
    "socket.socket(", "urllib.request.", "os.system(", "os.kill(", "shutil.rmtree(",
)


def test_core_wire_package_contains_no_dispatch_or_effect_code():
    wire_dir = Path(__file__).resolve().parent.parent / "a2a_compliance" / "wire"
    offenders = []
    for path in sorted(wire_dir.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN_TOKENS:
            if token in text:
                offenders.append(f"{path.name}: {token!r}")
    assert offenders == [], offenders
