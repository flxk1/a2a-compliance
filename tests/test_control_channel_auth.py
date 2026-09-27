"""Authenticated control channel (OWASP ASI07 quick win #1).

`ControlParticipant.checkpoint()` verifies every envelope before honouring it
when a `TrustStore` is configured (AUTHENTICATED mode): signature (via
`wire.signing`, never duplicated here), expiry, `(sender, nonce)` replay (via
the `wire.verification.NonceStore` port), and `authority.authorize()` for the
sender's claimed role. Any failure rejects the message -- it is never
applied -- and is reported back as `ack{accepted: False}` with a reason.
With no `TrustStore` configured (BARE/ADVISORY mode) an unsigned envelope is
still read and applied, but labelled advisory.

FIX 1(a) (key-bound sender identity): every `TrustBinding` registered below
now carries an explicit `identity=` matching the actor it signs as --
`ControlParticipant._verify_envelope` rejects an envelope whose `from_.actor`
does not equal its signing key's bound identity, exactly the same
key-bound-identity posture the identity leg already applies to
`HumanApprovalReceipt.approver`. See `tests/test_channel_identity_replay.py`
for the identity-mismatch regression itself.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from a2a_compliance import ControlParticipant, Verb
from a2a_compliance import envelope as env
from a2a_compliance.wire.signing import dev_sign_subject, generate_dev_keypair
from a2a_compliance.wire.trust import InMemoryTrustStore
from a2a_compliance.wire.verification import InMemoryNonceStore
from interfaces.a2a_control import Authority, Party

MAKER = "maker-1"
COMP = "comp-1"


@pytest.fixture
def keys():
    return {
        "comp": generate_dev_keypair(),
        "forger": generate_dev_keypair(),
        "rogue": generate_dev_keypair(),
    }


@pytest.fixture
def trust_store(keys):
    store = InMemoryTrustStore()
    store.add(
        "key-comp", keys["comp"][1],
        frozenset({"A2AControlMessage"}), frozenset({"policy-compliance"}),
        identity=COMP,  # FIX 1(a): from_.actor must equal the key-bound identity
    )
    # A key that legitimately signs as a MAKER role (e.g. "backend") -- valid
    # signature, but that role is not a compliance role, so `authorize()`
    # must still reject it.
    store.add(
        "key-rogue", keys["rogue"][1],
        frozenset({"A2AControlMessage"}), frozenset({"backend"}),
        identity="backend-x",
    )
    # key-forger is deliberately NEVER registered.
    return store


@pytest.fixture
def nonce_store():
    return InMemoryNonceStore()


@pytest.fixture
def maker(inbox, trust_store, nonce_store):
    return ControlParticipant(
        session_id=MAKER, inbox=inbox, compliance_actor=COMP,
        trust_store=trust_store, nonce_store=nonce_store,
        state_provider=lambda include: {},
    )


def _build_signed(
    *, priv_key, key_id, from_role="policy-compliance", from_actor=COMP,
    verb=Verb.HOLD, body=None, nonce=None, ttl_seconds=300, now=None,
):
    msg = env.new_message(
        from_=Party(actor=from_actor, role=from_role),
        to=Party(actor=MAKER, role="maker"),
        verb=verb,
        body=body if body is not None else env.hold_body("next-action"),
        authority=Authority(basis="role", role=from_role, oversees=MAKER, reserved=False),
    )
    wire = env.to_wire(msg)
    return env.stamp_and_sign(
        wire, key_id=key_id, sign=lambda d: dev_sign_subject(d, priv_key),
        nonce=nonce, ttl_seconds=ttl_seconds, now=now,
    )


# --- forged sender -----------------------------------------------------

def test_forged_sender_not_applied_reported_accepted_false(maker, inbox, keys):
    forged = _build_signed(priv_key=keys["forger"][0], key_id="key-forger")
    inbox.put(MAKER, forged)

    responses = maker.checkpoint()

    assert len(responses) == 1
    assert responses[0].verb is Verb.ACK
    assert responses[0].body["accepted"] is False
    assert responses[0].body.get("note")
    assert maker.is_held() is False  # never applied


# --- tampered payload ----------------------------------------------------

def test_tampered_payload_rejected(maker, inbox, keys):
    signed = _build_signed(priv_key=keys["comp"][0], key_id="key-comp")
    tampered = dict(signed)
    tampered["body"] = dict(tampered["body"])
    tampered["body"]["scope"] = "session"  # mutated after signing

    inbox.put(MAKER, tampered)
    responses = maker.checkpoint()

    assert responses[0].body["accepted"] is False
    assert maker.is_held() is False


# --- expired envelope ------------------------------------------------------

def test_expired_envelope_rejected(maker, inbox, keys):
    long_ago = datetime(2000, 1, 1, tzinfo=timezone.utc)
    expired = _build_signed(
        priv_key=keys["comp"][0], key_id="key-comp", now=long_ago, ttl_seconds=1,
    )

    inbox.put(MAKER, expired)
    responses = maker.checkpoint()

    assert responses[0].body["accepted"] is False
    assert "expired" in responses[0].body["note"]
    assert maker.is_held() is False


# --- replayed nonce ----------------------------------------------------

def test_replayed_nonce_rejected_on_second_delivery(maker, inbox, keys):
    resume = _build_signed(
        priv_key=keys["comp"][0], key_id="key-comp",
        verb=Verb.RESUME, body=env.resume_body("hold-1"), nonce="fixed-nonce-1",
    )

    inbox.put(MAKER, resume)
    first = maker.checkpoint()
    assert first[0].body["accepted"] is True

    # the identical envelope (same sender, same nonce) delivered again
    inbox.put(MAKER, resume)
    second = maker.checkpoint()
    assert second[0].body["accepted"] is False
    assert "replay" in second[0].body["note"]


# --- unauthorized role ---------------------------------------------------

def test_sender_role_unauthorized_for_verb_rejected(maker, inbox, keys):
    rogue = _build_signed(
        priv_key=keys["rogue"][0], key_id="key-rogue",
        from_role="backend", from_actor="backend-x",
    )

    inbox.put(MAKER, rogue)
    responses = maker.checkpoint()

    assert responses[0].body["accepted"] is False
    assert "compliance role" in responses[0].body["note"]
    assert maker.is_held() is False


# --- unsigned envelope in authenticated mode --------------------------

def test_unsigned_envelope_rejected_in_authenticated_mode(maker, inbox):
    msg = env.new_message(
        from_=Party(actor=COMP, role="policy-compliance"),
        to=Party(actor=MAKER, role="maker"),
        verb=Verb.HOLD,
        body=env.hold_body("next-action"),
        authority=Authority(basis="role", role="policy-compliance", oversees=MAKER),
    )
    inbox.put(MAKER, env.to_wire(msg))  # no nonce/expires_at/key_id/signature

    responses = maker.checkpoint()

    assert responses[0].body["accepted"] is False
    assert "unsigned" in responses[0].body["note"]
    assert maker.is_held() is False


# --- fail-closed when cryptography is unavailable --------------------------

def test_authenticated_mode_fails_closed_without_cryptography(maker, inbox, keys, monkeypatch):
    signed = _build_signed(priv_key=keys["comp"][0], key_id="key-comp")
    inbox.put(MAKER, signed)

    import a2a_compliance.wire.signing as signing_mod

    def _raise_import_error(*args, **kwargs):
        raise ImportError("cryptography is not installed")

    monkeypatch.setattr(signing_mod, "verify_signature", _raise_import_error)

    responses = maker.checkpoint()

    assert responses[0].body["accepted"] is False
    assert "cryptography" in responses[0].body["note"]
    assert maker.is_held() is False


# --- bare mode: unsigned reads as advisory --------------------------------

def test_bare_mode_reads_unsigned_envelope_as_advisory(inbox):
    bare_maker = ControlParticipant(
        session_id=MAKER, inbox=inbox, compliance_actor=COMP,
        state_provider=lambda include: {},
    )
    assert bare_maker.authenticated_mode is False

    msg = env.new_message(
        from_=Party(actor=COMP, role="policy-compliance"),
        to=Party(actor=MAKER, role="maker"),
        verb=Verb.HOLD,
        body=env.hold_body("next-action"),
        authority=Authority(basis="role", role="policy-compliance", oversees=MAKER),
    )
    inbox.put(MAKER, env.to_wire(msg))

    responses = bare_maker.checkpoint()

    assert responses[0].body["accepted"] is True
    assert responses[0].body["mode"] == "advisory"
    assert bare_maker.is_held() is True  # bare mode still applies it


def test_valid_authenticated_envelope_applied_and_labelled(maker, inbox, keys):
    signed = _build_signed(priv_key=keys["comp"][0], key_id="key-comp")
    inbox.put(MAKER, signed)

    responses = maker.checkpoint()

    assert responses[0].body["accepted"] is True
    assert responses[0].body["mode"] == "authenticated"
    assert maker.is_held() is True


# --- mailbox files are created 0600 -------------------------------------

def test_newly_created_mailbox_file_has_mode_0600(inbox):
    inbox.put(MAKER, {"id": "probe", "verb": "hold"})

    box = inbox.root / MAKER
    files = [f for f in box.glob("[0-9]" * 12 + "-*.json")]
    assert files, "expected at least one published mailbox file"
    for f in files:
        assert (f.stat().st_mode & 0o777) == 0o600
