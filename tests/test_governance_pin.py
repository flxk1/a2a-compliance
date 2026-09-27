"""Quick win 9 -- pinned governance block. `governance_block.GovernanceBlock.
digest()` (RFC 8785 via `wire.canonical`) plus `governance_block.
sign_governance_block` (reusing `wire.signing`'s DSSE construction, never a
second signature format) let `admission.admit()` check that the
`GovernanceBlock` a ruling actually used hashes to EXACTLY the digest a
distinct, trust-store-authorized policy author signed -- never the maker's
own signature, never a swapped-in block. Opt-in: `admit()` with no
`signed_governance_block` behaves exactly as before (the pre-existing
self-declared boundary).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from a2a_compliance import (
    ACTION_NO_STEER,
    CapabilityInventory,
    ComplianceTeam,
    ControlRequest,
    GovernanceBlock,
    GroundingContext,
    GroundingResult,
    TEAM_ROLES,
)
from a2a_compliance.governance_block import SignedGovernanceBlock, sign_governance_block
from a2a_compliance.team import TeamProfile
from a2a_compliance.wire.admission import AdmissionDecision, admit, dev_issuer
from a2a_compliance.wire.signing import generate_dev_keypair
from a2a_compliance.wire.trust import ANY, InMemoryTrustStore

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
MAKER_ID = "maker-1"
POLICY_AUTHOR_ROLE = "policy-author"

GOVERNANCE = GovernanceBlock.from_dict({"actions": [{"kind": "edit"}]})


def _full_inventory():
    tools, skills, contracts, distributions = set(), set(), set(), set()
    for role in TEAM_ROLES:
        for cap in role.capabilities:
            {"tool": tools, "skill": skills, "contract": contracts,
             "distribution": distributions}[cap.kind.value].add(cap.name)
    return CapabilityInventory.from_iterables(
        tools=tools, skills=skills, contracts=contracts, distributions=distributions,
    )


def _plan(governance, *, target_kind="edit", maker_id=MAKER_ID):
    # PROTOCOL profile: this test exercises the governance-block pin alone,
    # not the LOOMGROUND preflight-receipt gate (already covered by
    # test_wire_e2.py) -- no stage receipts are needed here.
    request = ControlRequest(
        GroundingContext(maker_id=maker_id, proposed_action={"bearer": maker_id, "action": target_kind}),
        target_kind, governance, profile=TeamProfile.PROTOCOL,
    )
    result = GroundingResult([], None, ACTION_NO_STEER, "test result")
    return ComplianceTeam(_full_inventory()).assess(request, result)


@pytest.fixture()
def keys():
    return {
        "policy_author": generate_dev_keypair(),
        "maker": generate_dev_keypair(),
        "untrusted": generate_dev_keypair(),
    }


def _trust_store(keys) -> InMemoryTrustStore:
    store = InMemoryTrustStore()
    store.add(
        "key-policy-author", keys["policy_author"][1],
        frozenset({"GovernanceBlock"}), frozenset({POLICY_AUTHOR_ROLE}),
    )
    # key-untrusted is deliberately NOT registered.
    return store


def _signed_by_policy_author(keys, *, block=GOVERNANCE) -> SignedGovernanceBlock:
    issuer = dev_issuer("key-policy-author", "policy:author-1", keys["policy_author"][0])
    return sign_governance_block(block, key_id=issuer.key_id, identity=issuer.identity, sign=issuer.sign)


# --- the positive path: a distinct, authorized policy author -> admitted --

def test_valid_signed_block_by_a_distinct_policy_author_admits_and_pins_digest(keys):
    plan = _plan(GOVERNANCE)
    signed = _signed_by_policy_author(keys)

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=_trust_store(keys),
        signed_governance_block=signed, policy_author_role=POLICY_AUTHOR_ROLE, now=NOW,
    )
    assert result.decision is AdmissionDecision.ADMITTED, result.reasons
    assert result.governance_block_digest == GOVERNANCE.digest()
    assert result.governance_block_digest == signed.digest


def test_admit_without_a_signed_block_behaves_as_before_unpinned(keys):
    plan = _plan(GOVERNANCE)
    result = admit(plan, [], governance=GOVERNANCE, trust_store=_trust_store(keys), now=NOW)
    assert result.decision is AdmissionDecision.ADMITTED, result.reasons
    assert result.governance_block_digest is None


# --- tampered block: digest mismatch --------------------------------------

def test_tampered_block_is_not_admitted(keys):
    """The block the ruling actually used no longer hashes to what the
    policy author signed (e.g. an attacker widened `actions[]` after
    signing) -- refused/held, never admitted."""
    signed = _signed_by_policy_author(keys)  # signs the ORIGINAL GOVERNANCE
    tampered_governance = GovernanceBlock.from_dict({
        "actions": [{"kind": "edit"}, {"kind": "wipe-everything"}],  # widened after signing
    })
    plan = _plan(tampered_governance)

    result = admit(
        plan, [], governance=tampered_governance, trust_store=_trust_store(keys),
        signed_governance_block=signed, policy_author_role=POLICY_AUTHOR_ROLE, now=NOW,
    )
    assert result.decision is not AdmissionDecision.ADMITTED
    assert any("does not match the pinned, signed digest" in r for r in result.reasons)
    assert result.governance_block_digest is None


# --- maker-signed block: never admitted, regardless of key validity -------

def test_maker_signed_block_is_not_admitted(keys):
    trust_store = _trust_store(keys)
    # The maker's own key IS registered and IS authorized for the role --
    # the rejection must come from identity distinctness, not from trust.
    trust_store.add(
        "key-maker", keys["maker"][1], frozenset({"GovernanceBlock"}), frozenset({POLICY_AUTHOR_ROLE}),
    )
    maker_issuer = dev_issuer("key-maker", MAKER_ID, keys["maker"][0])
    signed_by_maker = sign_governance_block(
        GOVERNANCE, key_id=maker_issuer.key_id, identity=maker_issuer.identity, sign=maker_issuer.sign,
    )
    plan = _plan(GOVERNANCE, maker_id=MAKER_ID)

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=trust_store,
        signed_governance_block=signed_by_maker, policy_author_role=POLICY_AUTHOR_ROLE, now=NOW,
    )
    assert result.decision is not AdmissionDecision.ADMITTED
    assert any("signed by the maker" in r for r in result.reasons)
    assert result.governance_block_digest is None


# --- untrusted signer -------------------------------------------------------

def test_block_signed_by_an_unregistered_key_is_not_admitted(keys):
    untrusted_issuer = dev_issuer("key-untrusted", "policy:rogue", keys["untrusted"][0])
    signed_by_untrusted = sign_governance_block(
        GOVERNANCE, key_id=untrusted_issuer.key_id, identity=untrusted_issuer.identity, sign=untrusted_issuer.sign,
    )
    plan = _plan(GOVERNANCE)

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=_trust_store(keys),
        signed_governance_block=signed_by_untrusted, policy_author_role=POLICY_AUTHOR_ROLE, now=NOW,
    )
    assert result.decision is not AdmissionDecision.ADMITTED
    assert any("unknown key_id" in r for r in result.reasons)


def test_block_signed_by_a_key_not_authorized_for_the_policy_author_role_is_not_admitted(keys):
    trust_store = InMemoryTrustStore()
    # Registered and bound to the GovernanceBlock object type, but NOT the
    # required policy-author role.
    trust_store.add(
        "key-policy-author", keys["policy_author"][1], frozenset({"GovernanceBlock"}), frozenset({"some-other-role"}),
    )
    signed = _signed_by_policy_author(keys)
    plan = _plan(GOVERNANCE)

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=trust_store,
        signed_governance_block=signed, policy_author_role=POLICY_AUTHOR_ROLE, now=NOW,
    )
    assert result.decision is not AdmissionDecision.ADMITTED
    assert any("key not bound to role" in r for r in result.reasons)


def test_block_signed_by_a_key_not_authorized_for_the_object_type_is_not_admitted(keys):
    trust_store = InMemoryTrustStore()
    # Registered and bound to the right role, but not the GovernanceBlock
    # object type (e.g. it is only trusted for a StageReceipt).
    trust_store.add(
        "key-policy-author", keys["policy_author"][1], frozenset({"StageReceipt"}), frozenset({POLICY_AUTHOR_ROLE}),
    )
    signed = _signed_by_policy_author(keys)
    plan = _plan(GOVERNANCE)

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=trust_store,
        signed_governance_block=signed, policy_author_role=POLICY_AUTHOR_ROLE, now=NOW,
    )
    assert result.decision is not AdmissionDecision.ADMITTED
    assert any("not authorized to sign a GovernanceBlock" in r for r in result.reasons)


# --- forged signature -------------------------------------------------------

def test_forged_signature_over_a_correct_digest_is_not_admitted(keys):
    signed = _signed_by_policy_author(keys)
    forged = SignedGovernanceBlock(
        block=signed.block, digest=signed.digest, signer_key_id=signed.signer_key_id,
        signer_identity=signed.signer_identity, signature="",  # forged/blank
    )
    plan = _plan(GOVERNANCE)

    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=_trust_store(keys),
        signed_governance_block=forged, policy_author_role=POLICY_AUTHOR_ROLE, now=NOW,
    )
    assert result.decision is not AdmissionDecision.ADMITTED
    assert any("signature verification failed" in r for r in result.reasons)


# --- digest determinism -----------------------------------------------------

def test_digest_is_deterministic_and_order_independent():
    a = GovernanceBlock.from_dict({
        "actions": [{"kind": "edit"}, {"kind": "read"}],
        "prohibited": ["push"],
        "reserved": [{"kind": "commit", "by": "human"}],
        "obligations": ["tests-green"],
    })
    b = GovernanceBlock.from_dict({
        "reserved": [{"kind": "commit", "by": "human"}],
        "obligations": ["tests-green"],
        "actions": [{"kind": "read"}, {"kind": "edit"}],
        "prohibited": ["push"],
    })
    assert a.digest() == b.digest()

    c = GovernanceBlock.from_dict({"actions": [{"kind": "edit"}]})
    assert a.digest() != c.digest()
