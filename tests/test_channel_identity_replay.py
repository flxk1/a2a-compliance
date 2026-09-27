"""G2 regression suite: control-channel identity binding + fail-closed replay
(FIX 1 / FIX 2), turning the two recorded exploit scripts into pytest
regressions.

`exploit.py` (self-signed agent-key halt receipt): a sender's OWN agent key
-- authorized for `HumanApprovalReceipt` but bound to no human role/identity
-- signs a receipt that merely self-declares a human `approver`, then
replays that same receipt on a second `halt()` call. Before this fix
`ComplianceAgent._verify_halt_approval` called the plain `wire.verification.
verify` (never checked the signing key's bound role/identity against the
claimed approver) and never consumed the receipt's nonce, so both the
self-signed receipt AND its replay were honoured.

`replay.py` (fail-open replay with no nonce store): a `ControlParticipant`
configured with a `trust_store` but no explicit `nonce_store` honoured the
SAME signed envelope twice, because the old `_verify_envelope` only ran its
replay check `if self.nonce_store is not None`.

Run against HEAD (27c9cff) and the identity leg's commit (5171dec) before
this file's companion fix: every test below either fails outright or raises
(`ComplianceAgent`/`ControlParticipant` accept what they must reject). The
recorded pre-fix pytest output is kept in the maker's report, not duplicated
here -- this docstring is not evidence, the actual run is.
"""

from __future__ import annotations

import stat
import tempfile
from pathlib import Path

import pytest

from a2a_compliance import ComplianceAgent, ControlParticipant, Roster, Verb
from a2a_compliance import envelope as env
from a2a_compliance.authority import HUMAN_ROLE
from a2a_compliance.inbox import FileInbox
from a2a_compliance.nonce_store import FileNonceStore
from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import dev_issuer
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryTrustStore

MAKER = "maker-1"
COMP = "comp-1"


# --- exploit.py, reproduced as a regression -------------------------------


@pytest.fixture
def exploit_setup(inbox):
    """Exact shape of `exploit.py`: the sender's own agent key, bound for
    `HumanApprovalReceipt`/`A2AControlMessage` and role `policy-compliance`
    only -- never `human`, and no bound identity."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-comp-1-agent", pub,
        frozenset({"HumanApprovalReceipt", "A2AControlMessage"}),
        frozenset({"policy-compliance"}),
    )
    comp = ComplianceAgent(
        session_id=COMP, role="policy-compliance", inbox=inbox,
        roster=Roster(), trust_store=trust_store,
    )

    def receipt(nonce="n1"):
        r = {
            "schema_version": "1.0.0", "type": "HumanApprovalReceipt",
            "issuer": "issuer:comp-1",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "run_id": "run-1", "nonce": nonce, "key_id": "key-comp-1-agent",
            "approver": {"id": "not-me-honest", "role": "human"},
            "permitted_action_digest": env.halt_digest(COMP, MAKER, "off-mandate"),
            "scope": "next-action", "reservations": [],
        }
        r["subject_digest"] = canonical.subject_digest(r)
        r["signature"] = dev_sign_subject(r, priv)
        return r

    return comp, receipt


def test_self_signed_agent_key_halt_receipt_is_rejected(exploit_setup):
    comp, receipt = exploit_setup
    res = comp.halt(MAKER, reason_ref="off-mandate", approval=receipt("n1"))
    assert res.dispatched is False
    assert res.surfaced_to_human is True


def test_self_signed_agent_key_halt_receipt_replay_is_also_rejected(exploit_setup):
    """The forged receipt is rejected BOTH the first and the second time --
    it never becomes valid by virtue of repetition."""
    comp, receipt = exploit_setup
    r = receipt("n1")
    first = comp.halt(MAKER, reason_ref="off-mandate", approval=r)
    second = comp.halt(MAKER, reason_ref="off-mandate", approval=r)
    assert first.dispatched is False
    assert second.dispatched is False


# --- a genuinely valid human receipt is single-use ------------------------


@pytest.fixture
def valid_receipt_setup(inbox):
    approver_priv, approver_pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-human-1", approver_pub, frozenset({"HumanApprovalReceipt"}),
        frozenset({HUMAN_ROLE}), identity="human-1",
    )
    comp = ComplianceAgent(
        session_id=COMP, role="policy-compliance", inbox=inbox,
        roster=Roster(), trust_store=trust_store,
    )

    def receipt(*, nonce="nonce-1", run_id="run-1", scope="next-action"):
        r = {
            "schema_version": "1.0.0", "type": "HumanApprovalReceipt",
            "issuer": "issuer:human-1",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "run_id": run_id, "nonce": nonce, "key_id": "key-human-1",
            "approver": {"id": "human-1", "role": HUMAN_ROLE},
            "permitted_action_digest": env.halt_digest(COMP, MAKER, "off-mandate"),
            "scope": scope, "reservations": [],
        }
        r["subject_digest"] = canonical.subject_digest(r)
        r["signature"] = dev_sign_subject(r, approver_priv)
        return r

    return comp, receipt


def test_valid_human_receipt_dispatches_once_and_second_use_is_denied(valid_receipt_setup):
    comp, receipt = valid_receipt_setup
    r = receipt()
    first = comp.halt(MAKER, reason_ref="off-mandate", approval=r)
    assert first.dispatched is True

    second = comp.halt(MAKER, reason_ref="off-mandate", approval=r)
    assert second.dispatched is False
    assert second.surfaced_to_human is True


def test_receipt_scope_unknown_value_is_rejected(valid_receipt_setup):
    comp, receipt = valid_receipt_setup
    r = receipt(scope="whenever")
    res = comp.halt(MAKER, reason_ref="off-mandate", approval=r)
    assert res.dispatched is False


# --- replay.py, reproduced as a regression --------------------------------


def test_replayed_signed_hold_envelope_rejected_without_explicit_nonce_store(inbox):
    """A `ControlParticipant` configured with a `trust_store` but NO explicit
    `nonce_store` must still reject a replayed signed envelope -- the
    default durable `FileNonceStore` (documented in `participant.py`) closes
    the fail-open gap `replay.py` exploited."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-comp", pub, frozenset({"A2AControlMessage"}), frozenset({"policy-compliance"}),
        identity=COMP,
    )
    comp = ComplianceAgent(
        session_id=COMP, role="policy-compliance", inbox=inbox, roster=Roster(),
        trust_store=trust_store, signer=dev_issuer("key-comp", COMP, priv),
    )
    maker = ControlParticipant(
        session_id=MAKER, inbox=inbox, compliance_actor=COMP, trust_store=trust_store,
    )  # deliberately no nonce_store passed

    comp.hold(MAKER)
    files = sorted(p for p in Path(inbox.root).rglob("*.json") if MAKER in str(p))
    wire = __import__("json").loads(files[0].read_text())

    first = maker.checkpoint()
    assert first[0].body["accepted"] is True

    inbox.put(MAKER, wire)  # replay the identical signed envelope
    second = maker.checkpoint()
    assert second[0].body["accepted"] is False
    assert "replay" in second[0].body["note"]


def test_authenticated_mode_never_skips_replay_check_without_nonce_store(inbox):
    """Direct check of the FIX 2(c) invariant: in authenticated mode, a
    `ControlParticipant` constructed with no `nonce_store` argument still
    ends up with a non-None, durable nonce store -- the replay check path
    is never silently skipped."""
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add("key-comp", pub, frozenset({"A2AControlMessage"}), frozenset({"policy-compliance"}), identity=COMP)
    maker = ControlParticipant(session_id=MAKER, inbox=inbox, compliance_actor=COMP, trust_store=trust_store)
    assert maker.nonce_store is not None


# --- FIX 1(a): from_.actor must equal the signing key's bound identity ----


def test_envelope_actor_not_equal_to_key_identity_is_rejected(inbox):
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-comp", pub, frozenset({"A2AControlMessage"}), frozenset({"policy-compliance"}),
        identity="the-real-comp-1",  # bound identity...
    )
    maker = ControlParticipant(session_id=MAKER, inbox=inbox, compliance_actor=COMP, trust_store=trust_store)

    from interfaces.a2a_control import Authority, Party

    msg = env.new_message(
        from_=Party(actor="impersonating-comp", role="policy-compliance"),  # ...but claims a different actor
        to=Party(actor=MAKER, role="maker"),
        verb=Verb.HOLD, body=env.hold_body("next-action"),
        authority=Authority(basis="role", role="policy-compliance", oversees=MAKER),
    )
    wire = env.to_wire(msg)
    wire = env.stamp_and_sign(wire, key_id="key-comp", sign=lambda d: dev_sign_subject(d, priv))
    inbox.put(MAKER, wire)

    responses = maker.checkpoint()
    assert responses[0].body["accepted"] is False
    assert "identity" in responses[0].body["note"]
    assert maker.is_held() is False


# --- NonceStore file permissions -------------------------------------------


def test_file_nonce_store_permissions_are_0600_and_0700():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "nonces"
        store = FileNonceStore(root)
        assert (root.stat().st_mode & 0o777) == 0o700

        assert store.consume("run-1", "nonce-1") is True
        assert store.consume("run-1", "nonce-1") is False

        files = list(root.glob("*.nonce"))
        assert files, "expected a nonce marker file"
        for f in files:
            assert stat.S_IMODE(f.stat().st_mode) == 0o600
