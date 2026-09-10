"""Role-based authority model (SPEC §5.1)."""

from a2a_compliance import Verb, Roster, authorize


def test_compliance_role_may_steer_overseen_maker():
    for verb in (Verb.QUERY_STATE, Verb.ISSUE_DIRECTIVE, Verb.HOLD, Verb.RESUME):
        a = authorize(from_role="policy-compliance", verb=verb, maker_id="m1")
        assert a.allowed, verb
        assert a.reserved is False
        assert a.role == "policy-compliance"


def test_halt_is_authorized_but_reserved():
    a = authorize(from_role="policy-compliance", verb=Verb.HALT, maker_id="m1")
    assert a.allowed is True
    assert a.reserved is True  # surfaced to the human before dispatch


def test_maker_role_may_not_steer_out_of_role():
    a = authorize(from_role="backend", verb=Verb.ISSUE_DIRECTIVE, maker_id="m1")
    assert a.allowed is False
    assert "not a compliance role" in a.reason


def test_compliance_role_not_overseeing_maker_is_denied():
    roster = Roster(oversight={"policy-compliance": {"m1"}}, oversees_all=True)
    # policy-compliance explicitly oversees only m1 -> denied for m2
    a = authorize(from_role="policy-compliance", verb=Verb.ISSUE_DIRECTIVE,
                  maker_id="m2", roster=roster)
    assert a.allowed is False
    assert "does not oversee" in a.reason


def test_maker_to_compliance_verb_not_driven_by_model():
    a = authorize(from_role="policy-compliance", verb=Verb.REPORT_STATE, maker_id="m1")
    assert a.allowed is False
    assert "maker->compliance" in a.reason


def test_default_roster_oversees_all():
    a = authorize(from_role="verify", verb=Verb.HOLD, maker_id="any-maker")
    assert a.allowed is True
