"""E3 exit criterion, proven end to end with a REAL subprocess: "governed
tools are unreachable except through the adapter in the test deployment;
bypass, reuse, drift and argument mutation are rejected" (plan). Exercises
`examples/subprocess_adapter.py` -- NOT core, the conformance adapter --
never `a2a_compliance.wire` directly calling a process.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from examples.subprocess_adapter import GOVERNED_TOOL, SubprocessAdapter  # noqa: E402

from a2a_compliance.wire import canonical  # noqa: E402
from a2a_compliance.wire.admission import AdmissionDecision, AdmissionResult, dev_issuer, issue_permit  # noqa: E402
from a2a_compliance.wire.executor import bind_constraints  # noqa: E402
from a2a_compliance.wire.signing import generate_dev_keypair  # noqa: E402
from a2a_compliance.wire.trust import InMemoryRevocationStore, InMemoryTrustStore  # noqa: E402
from a2a_compliance.wire.verification import InMemoryNonceStore, verify  # noqa: E402

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
FAR_FUTURE = NOW + timedelta(hours=1)


@pytest.fixture()
def keys():
    return {"issuer": generate_dev_keypair(), "recorder": generate_dev_keypair()}


@pytest.fixture()
def deployment(keys):
    """One conformance deployment: a trust store, a fresh nonce store, a
    fresh `SubprocessAdapter` (with its own `GovernedEchoExecutor`,
    `calls` starting empty)."""
    trust_store = InMemoryTrustStore()
    trust_store.add("key-issuer", keys["issuer"][1], frozenset({"ExecutionPermit"}), frozenset())
    trust_store.add("key-recorder", keys["recorder"][1], frozenset({"ToolReceipt"}), frozenset())
    nonce_store = InMemoryNonceStore()
    revocation_store = InMemoryRevocationStore()
    sub_adapter = SubprocessAdapter(
        trust_store=trust_store, nonce_store=nonce_store,
        signer=dev_issuer("key-recorder", "recorder:enforcement", keys["recorder"][0]),
        revocation_store=revocation_store,
    )
    return sub_adapter, trust_store, nonce_store, revocation_store


def _permit(
    keys, nonce_store, arguments, *, run_id="run-adapter-0001", nonce="permit-nonce-1",
    expires_at=FAR_FUTURE, grade="mediated",
):
    action_digest = canonical.digest_hex({"run": run_id, "nonce": nonce})
    admission = AdmissionResult(AdmissionDecision.ADMITTED, action_digest, "run-tool")
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade=grade, adapter="subprocess",
        run_id=run_id, nonce=nonce, expires_at=expires_at, nonce_store=nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=NOW,
    )
    assert result.ok, result.reasons
    return result.permit


# --- positive: the ONLY way to reach the real subprocess -------------------

def test_valid_permit_runs_the_real_subprocess_and_yields_a_verifiable_receipt(keys, deployment):
    sub_adapter, trust_store, nonce_store, _ = deployment
    arguments = {"message": "hello-e3"}
    permit = _permit(keys, nonce_store, arguments)

    receipts, result = sub_adapter.consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, dispatch_id="dispatch-adapter-1", now=NOW,
    )
    assert result.ok, result.reasons
    assert len(receipts) == 1
    assert sub_adapter.executor.calls == [(GOVERNED_TOOL, arguments)]

    receipt = receipts[0]
    verified = verify(receipt, "ToolReceipt", trust_store=trust_store, now=NOW)
    assert verified.ok, verified.errors
    assert receipt["tool"] == GOVERNED_TOOL
    assert receipt["action_digest"] == permit["action_digest"]


def test_enforcement_grade_reports_mediated_when_bypass_is_genuinely_rejected(deployment):
    sub_adapter, _trust_store, _nonce_store, _revocation_store = deployment
    assert sub_adapter.enforcement_grade() == "mediated"
    # the live self-check above must not itself have produced a real effect.
    assert sub_adapter.executor.calls == []


# --- bypass: no path to `echo` except a valid permit through the adapter --

def test_bypass_no_permit_leaves_the_real_subprocess_uncalled(deployment):
    sub_adapter, *_ = deployment
    receipts, result = sub_adapter.consume_and_execute(
        None, tool=GOVERNED_TOOL, arguments={"message": "should-not-run"},
        dispatch_id="bypass-1", now=NOW,
    )
    assert result.ok is False
    assert receipts == []
    assert sub_adapter.executor.calls == []


def test_bypass_tampered_permit_leaves_the_real_subprocess_uncalled(keys, deployment):
    sub_adapter, _trust_store, nonce_store, _ = deployment
    arguments = {"message": "should-not-run"}
    permit = dict(_permit(keys, nonce_store, arguments))
    permit["run_id"] = "attacker-supplied-run-id"  # subject changes, signature is now stale

    receipts, result = sub_adapter.consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, dispatch_id="bypass-2", now=NOW,
    )
    assert result.ok is False
    assert receipts == []
    assert sub_adapter.executor.calls == []


# --- reuse: a second dispatch of the same permit never runs the process ---

def test_reuse_leaves_the_real_subprocess_called_only_once(keys, deployment):
    sub_adapter, _trust_store, nonce_store, _ = deployment
    arguments = {"message": "once-only"}
    permit = _permit(keys, nonce_store, arguments)

    first_receipts, first = sub_adapter.consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, dispatch_id="d1", now=NOW,
    )
    assert first.ok
    assert len(first_receipts) == 1

    second_receipts, second = sub_adapter.consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, dispatch_id="d2", now=NOW,
    )
    assert second.ok is False
    assert second_receipts == []
    assert len(sub_adapter.executor.calls) == 1


# --- drift: a permit valid at admission, expired by execution time --------

def test_drift_expired_permit_leaves_the_real_subprocess_uncalled(keys, deployment):
    sub_adapter, _trust_store, nonce_store, _ = deployment
    arguments = {"message": "too-late"}
    permit = _permit(keys, nonce_store, arguments, expires_at=NOW + timedelta(minutes=1))

    receipts, result = sub_adapter.consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, dispatch_id="d",
        now=NOW + timedelta(hours=1),
    )
    assert result.ok is False
    assert receipts == []
    assert sub_adapter.executor.calls == []


def test_drift_revoked_key_leaves_the_real_subprocess_uncalled(keys, deployment):
    sub_adapter, _trust_store, nonce_store, revocation_store = deployment
    arguments = {"message": "revoked"}
    permit = _permit(keys, nonce_store, arguments)
    revocation_store.revoke("key", "key-issuer", NOW - timedelta(minutes=1))

    receipts, result = sub_adapter.consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert receipts == []
    assert sub_adapter.executor.calls == []


# --- argument mutation: the real subprocess never runs on a mismatch ------

def test_argument_mutation_leaves_the_real_subprocess_uncalled(keys, deployment):
    sub_adapter, _trust_store, nonce_store, _ = deployment
    permit = _permit(keys, nonce_store, {"message": "the-permitted-message"})

    receipts, result = sub_adapter.consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments={"message": "a-different-message"},
        dispatch_id="d", now=NOW,
    )
    assert result.ok is False
    assert receipts == []
    assert sub_adapter.executor.calls == []


# --- the governed tool is unreachable except through the adapter ----------

def test_no_other_public_path_to_the_governed_executor(deployment):
    sub_adapter, *_ = deployment
    public_adapter_methods = {
        name for name in vars(type(sub_adapter))
        if not name.startswith("_") and callable(getattr(type(sub_adapter), name))
    }
    assert public_adapter_methods == {"consume_and_execute", "enforcement_grade"}
    public_executor_methods = {
        name for name in vars(type(sub_adapter.executor))
        if not name.startswith("_") and callable(getattr(type(sub_adapter.executor), name))
    }
    assert public_executor_methods == {"execute"}
