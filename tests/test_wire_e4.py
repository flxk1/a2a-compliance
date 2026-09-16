"""E4 conformance suite: postflight assurance (`a2a_compliance.wire.reconciliation`,
`.certification`, `.obligations`, `.audit_chain`).

Exit criterion under test throughout: a successful `ToolReceipt` alone can
never certify; only matching effects AND discharged blocking obligations
(both independently VERIFIED, never caller-asserted) can.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import AdmissionDecision, AdmissionResult, dev_issuer, issue_permit
from a2a_compliance.wire.audit_chain import audit_chain_verify
from a2a_compliance.wire.certification import CertificationResult, InMemoryFreshness, certify
from a2a_compliance.wire.executor import ExecutionOutcome, bind_constraints, consume_and_execute
from a2a_compliance.wire.obligations import issue_discharge_receipt
from a2a_compliance.wire.reconciliation import ObservedEffects, ReconciliationResult, reconcile
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryRevocationStore, InMemoryTrustStore
from a2a_compliance.wire.verification import InMemoryNonceStore, verify

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
FAR_FUTURE = NOW + timedelta(hours=1)


class FakeExecutor:
    def __init__(self, effect=None) -> None:
        self.effect = effect if effect is not None else {"ok": True}
        self.calls: list = []

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome:
        self.calls.append((tool, dict(arguments)))
        return ExecutionOutcome(effect=self.effect, executor_id="exec:e4-1", executor_role="tool-executor")


@pytest.fixture()
def keys():
    return {
        "issuer": generate_dev_keypair(),
        "recorder": generate_dev_keypair(),
        "reconciler": generate_dev_keypair(),
        "certifier": generate_dev_keypair(),
        "discharger": generate_dev_keypair(),
        "forger": generate_dev_keypair(),
    }


def _trust_store(keys) -> InMemoryTrustStore:
    store = InMemoryTrustStore()
    store.add("key-issuer", keys["issuer"][1], frozenset({"ExecutionPermit"}), frozenset())
    store.add("key-recorder", keys["recorder"][1], frozenset({"ToolReceipt"}), frozenset())
    store.add("key-reconciler", keys["reconciler"][1], frozenset({"Reconciliation"}), frozenset())
    store.add("key-certifier", keys["certifier"][1], frozenset({"OversightCertificate"}), frozenset())
    store.add("key-discharger", keys["discharger"][1], frozenset({"ObligationDischargeReceipt"}), frozenset())
    # key-forger is deliberately NOT registered under its own key_id.
    return store


def _admitted(action_digest: str) -> AdmissionResult:
    return AdmissionResult(AdmissionDecision.ADMITTED, action_digest, "edit")


def _permit(keys, tool, arguments, *, nonce_store, run_id="run-e4-0001", nonce="permit-nonce-1",
            grade="mediated", expires_at=FAR_FUTURE, action_digest=None):
    action_digest = action_digest or canonical.digest_hex({"kind": "edit", "run": run_id})
    admission = _admitted(action_digest)
    issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    result = issue_permit(
        admission, issuer=issuer, enforcement_grade=grade, adapter="subprocess",
        run_id=run_id, nonce=nonce, expires_at=expires_at, nonce_store=nonce_store,
        constraints=bind_constraints(tool, arguments), issued_at=NOW,
    )
    assert result.ok, result.reasons
    return result.permit


def _recorder(keys):
    return dev_issuer("key-recorder", "recorder:enforcement", keys["recorder"][0])


def _reconciler(keys):
    return dev_issuer("key-reconciler", "reconciler:enforcement", keys["reconciler"][0])


def _certifier(keys):
    return dev_issuer("key-certifier", "certifier:enforcement", keys["certifier"][0])


def _discharger(keys):
    return dev_issuer("key-discharger", "discharger:enforcement", keys["discharger"][0])


def _dispatch(keys, permit, tool, arguments, *, nonce_store, effect=None, dispatch_id="dispatch-1"):
    executor = FakeExecutor(effect)
    result = consume_and_execute(
        permit, tool=tool, arguments=arguments, trust_store=_trust_store(keys),
        nonce_store=nonce_store, executor=executor, signer=_recorder(keys),
        dispatch_id=dispatch_id, now=NOW,
    )
    assert result.ok, result.reasons
    return result.receipt


def _matching_observed(receipt, effect=None) -> ObservedEffects:
    effect = effect if effect is not None else {"ok": True}
    return ObservedEffects(effects={canonical.subject_digest(receipt): effect})


# --- positive: a fully complete, admitted, effect-matched run --------------

def test_full_run_produces_one_verifiable_oversight_certificate(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)

    recon = reconcile(
        permit, [receipt], _matching_observed(receipt),
        trust_store=trust_store, signer=_reconciler(keys),
        run_id="run-e4-0001", nonce="recon-nonce-1", now=NOW,
    )
    assert recon.ok, recon.reasons
    assert recon.reconciliation["certified"] is True
    assert recon.reconciliation["residuals"] == []
    assert verify(recon.reconciliation, "Reconciliation", trust_store=trust_store, now=NOW).ok

    action_digest = permit["action_digest"]
    discharge = issue_discharge_receipt(
        "obligation-1", action_digest, discharger=_discharger(keys),
        run_id="run-e4-0001", nonce="discharge-nonce-1", expires_at=FAR_FUTURE, issued_at=NOW,
    )
    fresh = InMemoryFreshness()

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        discharge_receipts=[discharge], blocking_obligations=["obligation-1"],
        mandatory_sources=["statute-x"], freshness=fresh,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-1", now=NOW,
    )
    assert cert.ok, cert.reasons
    certificate = cert.certificate
    assert certificate["type"] == "OversightCertificate"
    assert certificate["permit_digest"] == canonical.subject_digest(permit)
    assert certificate["reconciliation_digest"] == canonical.subject_digest(recon.reconciliation)
    assert certificate["tool_receipt_digests"] == [canonical.subject_digest(receipt)]
    assert certificate["discharged_obligation_digests"] == [canonical.subject_digest(discharge)]
    assert verify(certificate, "OversightCertificate", trust_store=trust_store, now=NOW).ok

    chain = audit_chain_verify(
        permit=permit, tool_receipts=[receipt], reconciliation=recon.reconciliation,
        certificate=certificate, trust_store=trust_store, now=NOW,
    )
    assert chain.ok, chain.errors


# --- 1. mismatched observed effects -> RESIDUAL_OPEN, not certified --------

def test_mismatched_observed_effects_yields_residual_open_not_certified(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store, effect={"ok": True})

    # Host independently observed something DIFFERENT from the receipt's
    # own self-reported effect -- a successful ToolReceipt exit is not
    # enough evidence by itself.
    observed = _matching_observed(receipt, effect={"ok": False, "tampered": True})

    recon = reconcile(
        permit, [receipt], observed, trust_store=trust_store, signer=_reconciler(keys),
        run_id="run-e4-0001", nonce="recon-nonce-mismatch", now=NOW,
    )
    assert recon.ok, recon.reasons
    assert recon.reconciliation["certified"] is False
    assert recon.reconciliation["residuals"] != []
    assert any("effect mismatch" in r for r in recon.reconciliation["residuals"])

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-mismatch", now=NOW,
    )
    assert cert.ok is False
    assert cert.certificate is None
    assert any("not a clean" in r for r in cert.reasons)


def test_missing_observed_effect_yields_residual_open(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)

    recon = reconcile(
        permit, [receipt], ObservedEffects(),  # host observed nothing at all
        trust_store=trust_store, signer=_reconciler(keys),
        run_id="run-e4-0001", nonce="recon-nonce-missing", now=NOW,
    )
    assert recon.ok, recon.reasons
    assert recon.reconciliation["certified"] is False
    assert any("missing observed effect" in r for r in recon.reconciliation["residuals"])


def test_unexpected_effect_with_no_receipt_yields_residual_open(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)

    observed = ObservedEffects(
        effects={canonical.subject_digest(receipt): {"ok": True}},
        unmatched=({"surprise": "unexplained-effect"},),
    )
    recon = reconcile(
        permit, [receipt], observed, trust_store=trust_store, signer=_reconciler(keys),
        run_id="run-e4-0001", nonce="recon-nonce-unexpected", now=NOW,
    )
    assert recon.ok, recon.reasons
    assert recon.reconciliation["certified"] is False
    assert any("unexpected effect" in r for r in recon.reconciliation["residuals"])


# --- 2. matching effects but an undischarged blocking obligation -----------

def test_undischarged_blocking_obligation_blocks_certification(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)

    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-2", now=NOW,
    )
    assert recon.ok and recon.reconciliation["certified"] is True

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        discharge_receipts=[],  # no discharge evidence at all
        blocking_obligations=["obligation-required"],
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-2", now=NOW,
    )
    assert cert.ok is False
    assert any("obligation-required" in r and "not discharged" in r for r in cert.reasons)


# --- 3. fabricated/unsigned/wrong-digest discharge receipt is rejected -----

def test_unsigned_discharge_receipt_does_not_count(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-3", now=NOW,
    )
    assert recon.ok

    fabricated = dict(issue_discharge_receipt(
        "obligation-1", permit["action_digest"], discharger=_discharger(keys),
        run_id="run-e4-0001", nonce="discharge-nonce-fabricated", expires_at=FAR_FUTURE, issued_at=NOW,
    ))
    fabricated["signature"] = ""  # strip the signature: fabricated/unsigned

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        discharge_receipts=[fabricated], blocking_obligations=["obligation-1"],
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-3", now=NOW,
    )
    assert cert.ok is False
    assert any("not discharged" in r for r in cert.reasons)


def test_wrong_key_signed_discharge_receipt_does_not_count(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-4", now=NOW,
    )
    assert recon.ok

    forged = dict(issue_discharge_receipt(
        "obligation-1", permit["action_digest"], discharger=_discharger(keys),
        run_id="run-e4-0001", nonce="discharge-nonce-forged", expires_at=FAR_FUTURE, issued_at=NOW,
    ))
    # Claims key-discharger (registered) but is actually signed by an
    # unrelated, unregistered private key.
    forged["signature"] = dev_sign_subject(forged, keys["forger"][0])

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        discharge_receipts=[forged], blocking_obligations=["obligation-1"],
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-4", now=NOW,
    )
    assert cert.ok is False
    assert any("not discharged" in r for r in cert.reasons)


def test_wrong_digest_discharge_receipt_does_not_count(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-5", now=NOW,
    )
    assert recon.ok

    tampered = dict(issue_discharge_receipt(
        "obligation-1", permit["action_digest"], discharger=_discharger(keys),
        run_id="run-e4-0001", nonce="discharge-nonce-tampered", expires_at=FAR_FUTURE, issued_at=NOW,
    ))
    tampered["obligation_id"] = "obligation-1-tampered-after-signing"  # subject changes, signature stays stale

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        discharge_receipts=[tampered], blocking_obligations=["obligation-1"],
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-5", now=NOW,
    )
    assert cert.ok is False
    assert any("not discharged" in r for r in cert.reasons)


# --- 4. stale mandatory source blocks certification -------------------------

def test_stale_mandatory_source_blocks_certification(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-6", now=NOW,
    )
    assert recon.ok

    fresh = InMemoryFreshness()
    fresh.mark_stale("statute-x")

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        mandatory_sources=["statute-x"], freshness=fresh,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-6", now=NOW,
    )
    assert cert.ok is False
    assert any("stale mandatory source" in r for r in cert.reasons)


def test_mandatory_source_with_no_freshness_port_blocks_certification(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-7", now=NOW,
    )
    assert recon.ok

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        mandatory_sources=["statute-x"], freshness=None,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-7", now=NOW,
    )
    assert cert.ok is False
    assert any("no freshness port" in r for r in cert.reasons)


# --- 5. non-ADMITTED run cannot certify (never retroactively admits) -------

def test_non_admitted_run_cannot_reconcile(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = dict(_permit(keys, tool, arguments, nonce_store=nonce_store))
    permit["adapter"] = "tampered-after-signing"  # subject changes, signature stays stale

    receipt_shaped = {
        "type": "ToolReceipt", "tool": tool, "arguments_digest": canonical.digest_hex(arguments),
        "effect_digest": canonical.digest_hex({"ok": True}), "action_digest": permit["action_digest"],
    }
    recon = reconcile(
        permit, [receipt_shaped], ObservedEffects(), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-8", now=NOW,
    )
    assert recon.ok is False
    assert recon.reconciliation is None
    assert any("subject_digest mismatch" in r for r in recon.reasons)


def test_forged_permit_cannot_certify(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-9", now=NOW,
    )
    assert recon.ok

    forged_permit = dict(permit)
    forged_permit["signature"] = dev_sign_subject(forged_permit, keys["forger"][0])

    cert = certify(
        forged_permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-9", now=NOW,
    )
    assert cert.ok is False
    assert any("does not verify" in r for r in cert.reasons)


def test_advisory_grade_permit_cannot_certify(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store, grade="advisory")
    receipt_shaped = {
        "type": "ToolReceipt", "tool": tool, "arguments_digest": canonical.digest_hex(arguments),
        "effect_digest": canonical.digest_hex({"ok": True}), "action_digest": permit["action_digest"],
    }
    recon = reconcile(
        permit, [receipt_shaped], ObservedEffects(), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-10", now=NOW,
    )
    assert recon.ok is False
    assert any("is not enforcement" in r for r in recon.reasons)


# --- 6. tampered certificate is rejected ------------------------------------

def test_tampered_certificate_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-11", now=NOW,
    )
    assert recon.ok
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-11", now=NOW,
    )
    assert cert.ok

    tampered = dict(cert.certificate)
    tampered["action_digest"] = "0" * 64  # subject changes, signature stays stale
    result = verify(tampered, "OversightCertificate", trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any("subject_digest mismatch" in e for e in result.errors)


# --- 7. broken run audit-chain is rejected ----------------------------------

def test_broken_audit_chain_tool_receipt_swap_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-12", now=NOW,
    )
    assert recon.ok
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-12", now=NOW,
    )
    assert cert.ok

    other_permit = _permit(
        keys, "delete-inbox", {"x": 1}, nonce_store=InMemoryNonceStore(),
        run_id="run-e4-other", nonce="permit-nonce-other",
        action_digest=canonical.digest_hex({"kind": "edit", "run": "run-e4-other"}),
    )
    swapped_receipt = _dispatch(
        keys, other_permit, "delete-inbox", {"x": 1}, nonce_store=InMemoryNonceStore(),
        dispatch_id="dispatch-swapped",
    )

    chain = audit_chain_verify(
        permit=permit, tool_receipts=[swapped_receipt], reconciliation=recon.reconciliation,
        certificate=cert.certificate, trust_store=trust_store, now=NOW,
    )
    assert chain.ok is False
    assert any("tool_receipt_digests" in e for e in chain.errors)


def test_broken_audit_chain_removed_tool_receipt_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-13", now=NOW,
    )
    assert recon.ok
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-13", now=NOW,
    )
    assert cert.ok

    chain = audit_chain_verify(
        permit=permit, tool_receipts=[], reconciliation=recon.reconciliation,
        certificate=cert.certificate, trust_store=trust_store, now=NOW,
    )
    assert chain.ok is False
    assert any("no tool receipts" in e for e in chain.errors)


def test_broken_audit_chain_mutated_reconciliation_is_rejected(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-14", now=NOW,
    )
    assert recon.ok
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-14", now=NOW,
    )
    assert cert.ok

    mutated_reconciliation = dict(recon.reconciliation)
    mutated_reconciliation["reason"] = "mutated after signing"

    chain = audit_chain_verify(
        permit=permit, tool_receipts=[receipt], reconciliation=mutated_reconciliation,
        certificate=cert.certificate, trust_store=trust_store, now=NOW,
    )
    assert chain.ok is False
    assert any("subject_digest mismatch" in e or "reconciliation_digest" in e for e in chain.errors)


# --- role separation ---------------------------------------------------------

def test_certifier_cannot_also_be_the_permit_issuer(keys):
    trust_store = InMemoryTrustStore()
    trust_store.add("key-issuer", keys["issuer"][1], frozenset({"ExecutionPermit", "Reconciliation", "OversightCertificate"}), frozenset())
    trust_store.add("key-recorder", keys["recorder"][1], frozenset({"ToolReceipt"}), frozenset())
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    executor = FakeExecutor()
    receipt_result = consume_and_execute(
        permit, tool=tool, arguments=arguments, trust_store=trust_store, nonce_store=nonce_store,
        executor=executor, signer=_recorder(keys), dispatch_id="dispatch-1", now=NOW,
    )
    assert receipt_result.ok
    receipt = receipt_result.receipt

    same_as_issuer = dev_issuer("key-issuer", "issuer:enforcement", keys["issuer"][0])
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=same_as_issuer, run_id="run-e4-0001", nonce="recon-nonce-role", now=NOW,
    )
    assert recon.ok

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=same_as_issuer, run_id="run-e4-0001", nonce="cert-nonce-role", now=NOW,
    )
    assert cert.ok is False
    assert any("permit issuer" in r for r in cert.reasons)


def test_certifier_cannot_also_be_the_tool_executor(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-role2", now=NOW,
    )
    assert recon.ok

    # A signer claiming the SAME identity the ToolReceipt records as the
    # executor -- even though it signs with a different (certifier) key.
    conflicted_signer = dev_issuer("key-certifier", "exec:e4-1", keys["certifier"][0])
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=conflicted_signer, run_id="run-e4-0001", nonce="cert-nonce-role2", now=NOW,
    )
    assert cert.ok is False
    assert any("tool executor" in r for r in cert.reasons)


def test_certifier_cannot_also_be_the_reconciler_same_identity(keys):
    # One principal signing both the Reconciliation and the OversightCertificate
    # could author a clean reconciliation and then certify it itself --
    # certify() trusts reconciliation["certified"] rather than re-deriving it
    # from ObservedEffects, so this is the most load-bearing separation.
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)

    same_identity = dev_issuer("key-reconciler", "shared:enforcement", keys["reconciler"][0])
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=same_identity, run_id="run-e4-0001", nonce="recon-nonce-role3", now=NOW,
    )
    assert recon.ok

    # Different key material, but declares the SAME identity string as the
    # reconciler that just signed this reconciliation.
    same_identity_different_key = dev_issuer(
        "key-certifier", "shared:enforcement", keys["certifier"][0],
    )
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=same_identity_different_key, run_id="run-e4-0001", nonce="cert-nonce-role3", now=NOW,
    )
    assert cert.ok is False
    assert any("reconciler" in r for r in cert.reasons)


def test_certifier_cannot_also_be_the_reconciler_same_key(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)

    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-role4", now=NOW,
    )
    assert recon.ok

    # Different declared identity, but the SAME underlying key_id as the
    # reconciler -- key_id equality alone must also be caught.
    same_key_different_identity = dev_issuer(
        "key-reconciler", "certifier-claiming-a-new-name:enforcement", keys["reconciler"][0],
    )
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=same_key_different_identity, run_id="run-e4-0001", nonce="cert-nonce-role4", now=NOW,
    )
    assert cert.ok is False
    assert any("reconciler" in r for r in cert.reasons)


def test_distinct_reconciler_and_certifier_still_certifies(keys):
    # Positive control for the fix above: distinct identities/keys for the
    # reconciler and certifier must still certify cleanly.
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)

    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-role5", now=NOW,
    )
    assert recon.ok

    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-role5", now=NOW,
    )
    assert cert.ok, cert.reasons
    assert verify(cert.certificate, "OversightCertificate", trust_store=trust_store, now=NOW).ok


# --- ObligationDischargeReceipt / OversightCertificate schema basics -------

def test_discharge_receipt_is_schema_valid_and_verifies(keys):
    receipt = issue_discharge_receipt(
        "obligation-x", "a" * 64, discharger=_discharger(keys),
        run_id="run-e4-schema", nonce="discharge-schema-1", expires_at=FAR_FUTURE, issued_at=NOW,
    )
    result = verify(receipt, "ObligationDischargeReceipt", trust_store=_trust_store(keys), now=NOW)
    assert result.ok, result.errors


def test_discharge_receipt_missing_obligation_id_is_schema_invalid(keys):
    receipt = dict(issue_discharge_receipt(
        "obligation-x", "a" * 64, discharger=_discharger(keys),
        run_id="run-e4-schema", nonce="discharge-schema-2", expires_at=FAR_FUTURE, issued_at=NOW,
    ))
    del receipt["obligation_id"]
    result = verify(receipt, "ObligationDischargeReceipt", trust_store=_trust_store(keys), now=NOW)
    assert result.ok is False
    assert any(e.startswith("schema:") for e in result.errors)


def test_certificate_missing_required_field_is_schema_invalid(keys):
    trust_store = _trust_store(keys)
    nonce_store = InMemoryNonceStore()
    tool, arguments = "send-email", {"to": "ops@example.com"}
    permit = _permit(keys, tool, arguments, nonce_store=nonce_store)
    receipt = _dispatch(keys, permit, tool, arguments, nonce_store=nonce_store)
    recon = reconcile(
        permit, [receipt], _matching_observed(receipt), trust_store=trust_store,
        signer=_reconciler(keys), run_id="run-e4-0001", nonce="recon-nonce-schema", now=NOW,
    )
    assert recon.ok
    cert = certify(
        permit, [receipt], recon.reconciliation, trust_store=trust_store,
        signer=_certifier(keys), run_id="run-e4-0001", nonce="cert-nonce-schema", now=NOW,
    )
    assert cert.ok
    broken = dict(cert.certificate)
    del broken["permit_digest"]
    del broken["signature"]  # would-be re-sign is pointless once required fields are gone
    result = verify({**broken, "signature": cert.certificate["signature"]}, "OversightCertificate", trust_store=trust_store, now=NOW)
    assert result.ok is False
    assert any(e.startswith("schema:") for e in result.errors)


# --- revocation reaches E4 types too (generalised via ALL_WIRE_TYPES) ------

def test_revoked_discharger_key_is_rejected(keys):
    trust_store = _trust_store(keys)
    revocation_store = InMemoryRevocationStore()
    revocation_store.revoke("key", "key-discharger", NOW - timedelta(minutes=1))
    receipt = issue_discharge_receipt(
        "obligation-x", "a" * 64, discharger=_discharger(keys),
        run_id="run-e4-schema", nonce="discharge-schema-3", expires_at=FAR_FUTURE, issued_at=NOW,
    )
    result = verify(
        receipt, "ObligationDischargeReceipt",
        trust_store=trust_store, revocation_store=revocation_store, now=NOW,
    )
    assert result.ok is False
    assert any("revoked: key_id" in e for e in result.errors)


# --- bare-install / lazy-reachability --------------------------------------

def test_e4_symbols_are_reachable_only_via_lazy_wire_getattr():
    from a2a_compliance import wire

    assert wire.reconcile is reconcile
    assert wire.certify is certify
    assert wire.issue_discharge_receipt is issue_discharge_receipt
    assert wire.audit_chain_verify is audit_chain_verify
    assert wire.ObservedEffects is ObservedEffects
    assert wire.ReconciliationResult is ReconciliationResult
    assert wire.CertificationResult is CertificationResult


def test_a_type_in_neither_wire_dict_is_refused_by_the_superset_gate():
    """E4 added ALL_WIRE_TYPES = WIRE_TYPES | E4_WIRE_TYPES. The verify() gate
    must stay fail-closed: an envelope whose type is in NEITHER dict is refused,
    never passed through as unvalidated."""
    from a2a_compliance.wire.schema_registry import E4_WIRE_TYPES, WIRE_TYPES
    from a2a_compliance.wire.verification import verify

    invented = "InventedGhostType"
    assert invented not in WIRE_TYPES and invented not in E4_WIRE_TYPES
    result = verify({"type": invented}, invented)
    assert result.ok is False
    assert any("unknown type" in e for e in result.errors)
