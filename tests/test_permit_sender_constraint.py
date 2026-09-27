"""Quick win 5 -- sender-constrained ExecutionPermit (RFC 7800 `cnf`,
DPoP-style). A permit carrying `aud` (the bound executor/adapter identity)
and `cnf.jkt` (the RFC 7638 thumbprint of the executor's Ed25519 public key,
as an RFC 8037 OKP JWK) may only be consumed by the caller who (a) claims
that same `executor_identity` AND (b) proves possession of the confirmed
key -- an Ed25519 signature over the canonical `{permit_id, nonce}` pair,
where `permit_id` is the permit's own `subject_digest`. Every rejection
path must produce NO effect and must NOT spend the permit's nonce: the
legitimate executor can always still consume it afterwards.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import AdmissionDecision, AdmissionResult, dev_issuer, issue_permit
from a2a_compliance.wire.executor import ExecutionOutcome, bind_constraints, consume_and_execute
from a2a_compliance.wire.signing import (
    cnf_jkt_for_public_key,
    dev_sign_proof_of_possession,
    generate_dev_keypair,
    okp_jwk,
)
from a2a_compliance.wire.trust import InMemoryTrustStore
from a2a_compliance.wire.verification import InMemoryNonceStore

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
FAR_FUTURE = NOW + timedelta(hours=1)

EXECUTOR_IDENTITY = "executor:real-adapter"
FOREIGN_IDENTITY = "executor:foreign-adapter"


class FakeExecutor:
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
        "executor": generate_dev_keypair(),  # the bound (aud/cnf) executor's own keypair
        "foreign": generate_dev_keypair(),   # a DIFFERENT key -- thumbprint != cnf.jkt
    }


def _trust_store(keys) -> InMemoryTrustStore:
    store = InMemoryTrustStore()
    store.add("key-issuer", keys["issuer"][1], frozenset({"ExecutionPermit"}), frozenset())
    store.add("key-recorder", keys["recorder"][1], frozenset({"ToolReceipt"}), frozenset())
    return store


def _signer(keys):
    return dev_issuer("key-recorder", "recorder:enforcement", keys["recorder"][0])


def _cnf(keys) -> dict:
    return {"jkt": cnf_jkt_for_public_key(keys["executor"][1])}


def _sender_constrained_permit(
    keys, tool, arguments, *, nonce_store, run_id="run-sc-0001", nonce="permit-nonce-1",
    aud=EXECUTOR_IDENTITY, cnf=None,
) -> dict:
    action_digest = canonical.digest_hex({"kind": "edit", "run": run_id})
    admission = AdmissionResult(AdmissionDecision.ADMITTED, action_digest, "edit")
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id=run_id, nonce=nonce, expires_at=FAR_FUTURE, nonce_store=nonce_store,
        constraints=bind_constraints(tool, arguments), issued_at=NOW,
        aud=aud, cnf=cnf if cnf is not None else _cnf(keys),
    )
    assert result.ok, result.reasons
    return result.permit


# --- permit issuance: aud/cnf are OPTIONAL, but must travel together -------

def test_permit_without_aud_or_cnf_is_not_sender_constrained(keys):
    """Back-compat: a permit carrying neither field skips this gate
    entirely -- `consume_and_execute` behaves exactly as before E5's quick
    win 5 for any host that never sets them."""
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    action_digest = canonical.digest_hex({"kind": "edit", "run": "run-unconstrained"})
    admission = AdmissionResult(AdmissionDecision.ADMITTED, action_digest, "edit")
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    tool, arguments = "send-email", {"to": "x"}
    issued = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-unconstrained", nonce="n1", expires_at=FAR_FUTURE, nonce_store=nonce_store,
        constraints=bind_constraints(tool, arguments), issued_at=NOW,
    )
    assert issued.ok, issued.reasons
    assert "aud" not in issued.permit and "cnf" not in issued.permit

    result = consume_and_execute(
        issued.permit, tool=tool, arguments=arguments,
        trust_store=_trust_store(keys), nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
    )
    assert result.ok, result.reasons
    assert executor.calls == [(tool, arguments)]


def test_aud_without_cnf_is_refused_at_issuance(keys):
    action_digest = canonical.digest_hex({"kind": "edit"})
    admission = AdmissionResult(AdmissionDecision.ADMITTED, action_digest, "edit")
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-x", nonce="n1", expires_at=FAR_FUTURE, nonce_store=InMemoryNonceStore(),
        constraints=bind_constraints("send-email", {"to": "x"}), issued_at=NOW,
        aud=EXECUTOR_IDENTITY,
    )
    assert result.ok is False
    assert any("aud was supplied without cnf" in r for r in result.reasons)


def test_cnf_without_aud_is_refused_at_issuance(keys):
    action_digest = canonical.digest_hex({"kind": "edit"})
    admission = AdmissionResult(AdmissionDecision.ADMITTED, action_digest, "edit")
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="subprocess",
        run_id="run-x", nonce="n1", expires_at=FAR_FUTURE, nonce_store=InMemoryNonceStore(),
        constraints=bind_constraints("send-email", {"to": "x"}), issued_at=NOW,
        cnf=_cnf(keys),
    )
    assert result.ok is False
    assert any("cnf was supplied without aud" in r for r in result.reasons)


# --- the positive path: matching aud + valid proof executes exactly once --

def test_matching_aud_and_valid_proof_executes_once(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _sender_constrained_permit(keys, tool, arguments, nonce_store=nonce_store)
    proof = dev_sign_proof_of_possession(permit["subject_digest"], permit["nonce"], keys["executor"][0])

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d1", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession=proof,
    )
    assert result.ok, result.reasons
    assert executor.calls == [(tool, arguments)]
    assert result.receipt["type"] == "ToolReceipt"

    # reuse: the same permit cannot dispatch a second time, even with a
    # perfectly valid proof the second time round.
    replay = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d2", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession=proof,
    )
    assert replay.ok is False
    assert executor.calls == [(tool, arguments)]


# --- aud mismatch: a different executor identity presenting the permit ----

def test_foreign_executor_identity_is_rejected_and_nonce_stays_unspent(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _sender_constrained_permit(keys, tool, arguments, nonce_store=nonce_store)
    proof = dev_sign_proof_of_possession(permit["subject_digest"], permit["nonce"], keys["executor"][0])

    foreign = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="foreign", now=NOW,
        executor_identity=FOREIGN_IDENTITY, proof_of_possession=proof,
    )
    assert foreign.ok is False
    assert any("aud mismatch" in r for r in foreign.reasons)
    assert executor.calls == []

    # the nonce was NEVER spent by the rejected attempt -- the legitimate
    # executor can still consume it.
    legit = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="legit", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession=proof,
    )
    assert legit.ok, legit.reasons
    assert executor.calls == [(tool, arguments)]


# --- wrong key: a valid signature, but from a key whose thumbprint doesn't
# match cnf.jkt --------------------------------------------------------------

def test_proof_from_a_key_not_matching_cnf_jkt_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _sender_constrained_permit(keys, tool, arguments, nonce_store=nonce_store)
    # A well-formed, internally-consistent proof -- but signed by a key
    # whose own thumbprint does not equal this permit's cnf.jkt.
    wrong_key_proof = dev_sign_proof_of_possession(
        permit["subject_digest"], permit["nonce"], keys["foreign"][0],
    )

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession=wrong_key_proof,
    )
    assert result.ok is False
    assert any("does not match the permit's cnf.jkt" in r for r in result.reasons)
    assert executor.calls == []

    legit = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="legit", now=NOW,
        executor_identity=EXECUTOR_IDENTITY,
        proof_of_possession=dev_sign_proof_of_possession(
            permit["subject_digest"], permit["nonce"], keys["executor"][0],
        ),
    )
    assert legit.ok, legit.reasons


# --- missing proof ----------------------------------------------------------

def test_missing_proof_is_rejected_and_nonce_stays_unspent(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _sender_constrained_permit(keys, tool, arguments, nonce_store=nonce_store)

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession=None,
    )
    assert result.ok is False
    assert any("proof of possession is required" in r for r in result.reasons)
    assert executor.calls == []

    legit = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="legit", now=NOW,
        executor_identity=EXECUTOR_IDENTITY,
        proof_of_possession=dev_sign_proof_of_possession(
            permit["subject_digest"], permit["nonce"], keys["executor"][0],
        ),
    )
    assert legit.ok, legit.reasons


# --- proof over the wrong permit id / nonce --------------------------------

def test_proof_over_a_different_permit_id_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _sender_constrained_permit(keys, tool, arguments, nonce_store=nonce_store)
    # Signed correctly by the bound key, but over a DIFFERENT permit_id.
    stale_proof = dev_sign_proof_of_possession("not-this-permit-id", permit["nonce"], keys["executor"][0])

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession=stale_proof,
    )
    assert result.ok is False
    assert any("does not verify" in r for r in result.reasons)
    assert executor.calls == []


def test_proof_over_a_different_nonce_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    executor = FakeExecutor()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _sender_constrained_permit(keys, tool, arguments, nonce_store=nonce_store)
    stale_proof = dev_sign_proof_of_possession(permit["subject_digest"], "some-other-nonce", keys["executor"][0])

    result = consume_and_execute(
        permit, tool=tool, arguments=arguments,
        trust_store=trust_store, nonce_store=nonce_store, executor=executor,
        signer=_signer(keys), dispatch_id="d", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession=stale_proof,
    )
    assert result.ok is False
    assert any("does not verify" in r for r in result.reasons)
    assert executor.calls == []


# --- malformed proof / cnf shapes are all fail-closed ----------------------

def test_malformed_proof_missing_jwk_is_rejected(keys):
    nonce_store = InMemoryNonceStore()
    permit = _sender_constrained_permit(keys, "send-email", {"to": "x"}, nonce_store=nonce_store)
    result = consume_and_execute(
        permit, tool="send-email", arguments={"to": "x"},
        trust_store=_trust_store(keys), nonce_store=nonce_store, executor=FakeExecutor(),
        signer=_signer(keys), dispatch_id="d", now=NOW,
        executor_identity=EXECUTOR_IDENTITY, proof_of_possession={"signature": "not-checked"},
    )
    assert result.ok is False
    assert any("jwk" in r for r in result.reasons)


def test_permit_with_cnf_missing_jkt_is_rejected(keys):
    # The schema itself already requires cnf.jkt (see execution-permit.
    # schema.json) -- a permit built with cnf={} is rejected at `verify()`,
    # step 1, before this gate's own cnf.jkt check is ever reached.
    nonce_store = InMemoryNonceStore()
    permit = _sender_constrained_permit(
        keys, "send-email", {"to": "x"}, nonce_store=nonce_store, cnf={},
    )
    result = consume_and_execute(
        permit, tool="send-email", arguments={"to": "x"},
        trust_store=_trust_store(keys), nonce_store=nonce_store, executor=FakeExecutor(),
        signer=_signer(keys), dispatch_id="d", now=NOW,
        executor_identity=EXECUTOR_IDENTITY,
        proof_of_possession=dev_sign_proof_of_possession(permit["subject_digest"], permit["nonce"], keys["executor"][0]),
    )
    assert result.ok is False
    assert any("jkt" in r and "required" in r for r in result.reasons)


# --- RFC 7638 thumbprint / RFC 8037 OKP JWK sanity -------------------------

def test_cnf_jkt_matches_the_okp_jwk_thumbprint_of_the_bound_key(keys):
    public_key = keys["executor"][1]
    jwk = okp_jwk(public_key)
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert cnf_jkt_for_public_key(public_key) == cnf_jkt_for_public_key(public_key)  # deterministic
    assert cnf_jkt_for_public_key(public_key) != cnf_jkt_for_public_key(keys["foreign"][1])
