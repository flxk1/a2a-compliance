"""Envelope + verb contract, schema validation, null-plane semantics (SPEC §3)."""

from a2a_compliance import Enforcement, Verb, Party, Authority, envelope as env, schema


def _auth():
    return Authority(basis="role", role="policy-compliance", oversees="m1", reserved=False)


def _party(actor, role):
    return Party(actor=actor, role=role)


def test_all_compliance_to_maker_verbs_validate():
    comp = _party("comp1", "policy-compliance")
    maker = _party("m1", "maker")
    msgs = [
        env.new_message(from_=comp, to=maker, verb=Verb.QUERY_STATE,
                        body=env.query_state_body(["trajectory", "tools"]), authority=_auth()),
        env.new_message(from_=comp, to=maker, verb=Verb.ISSUE_DIRECTIVE,
                        body=env.issue_directive_body("stay on mandate", "correct"), authority=_auth()),
        env.new_message(from_=comp, to=maker, verb=Verb.HOLD,
                        body=env.hold_body("next-action", conditions=["await review"]), authority=_auth()),
        env.new_message(from_=comp, to=maker, verb=Verb.RESUME,
                        body=env.resume_body("hold-123"), authority=_auth()),
    ]
    for m in msgs:
        wire = env.to_wire(m)
        assert schema.validate(wire) == [], f"{m.verb}: {schema.validate(wire)}"


def test_halt_body_and_reserved_authority_validate():
    comp = _party("comp1", "policy-compliance")
    maker = _party("m1", "maker")
    a = Authority(basis="role", role="policy-compliance", oversees="m1", reserved=True)
    m = env.new_message(from_=comp, to=maker, verb=Verb.HALT,
                        body=env.halt_body(reason_ref="off-mandate"), authority=a)
    wire = env.to_wire(m)
    assert schema.validate(wire) == []
    assert wire["body"]["irreversible"] is True
    assert wire["authority"]["reserved"] is True


def test_maker_to_compliance_verbs_validate():
    maker = _party("m1", "maker")
    comp = _party("comp1", "policy-compliance")
    a = Authority(basis="role", role="maker")
    report = env.new_message(from_=maker, to=comp, verb=Verb.REPORT_STATE,
                             body=env.report_state_body(trajectory=[{"step": "read"}]), authority=a)
    ack = env.new_message(from_=maker, to=comp, verb=Verb.ACK,
                          body=env.ack_body("dir-1", accepted=False, note="out of boundary"), authority=a)
    esc = env.new_message(from_=maker, to=comp, verb=Verb.ESCALATE,
                          body=env.escalate_body("cannot decide", "human"), authority=a)
    for m in (report, ack, esc):
        assert schema.validate(env.to_wire(m)) == []


def test_report_state_is_always_self_report_tier():
    body = env.report_state_body(claims=[{"ok": True}])
    assert body["provenance"] == "self-report"


def test_grounding_and_enforcement_null_in_phase1():
    comp = _party("comp1", "grounding")
    maker = _party("m1", "maker")
    m = env.new_message(from_=comp, to=maker, verb=Verb.QUERY_STATE,
                        body=env.query_state_body(["mandate"]), authority=_auth())
    assert m.grounding is None and m.enforcement is None
    wire = env.to_wire(m)
    assert wire["grounding"] is None and wire["enforcement"] is None
    assert schema.validate(wire) == []


def test_enforcement_engine_is_host_neutral():
    comp = _party("comp1", "grounding")
    maker = _party("m1", "maker")
    message = env.new_message(
        from_=comp,
        to=maker,
        verb=Verb.ISSUE_DIRECTIVE,
        body=env.issue_directive_body("narrow scope", "constrain"),
        authority=_auth(),
    )
    message.enforcement = Enforcement(engine="acme-gate", verdict="permit")

    wire = env.to_wire(message)

    assert schema.validate(wire) == []
    assert env.from_wire(wire).enforcement.engine == "acme-gate"


def test_receiver_does_not_treat_null_planes_as_failure():
    # A wire message with explicit null planes must parse and be valid.
    wire = {
        "protocol": "a2a-compliance/0.1",
        "id": "abc", "correlates": None, "ts": "2026-09-10T00:00:00+00:00",
        "from": {"actor": "comp1", "role": "verify"},
        "to": {"actor": "m1", "role": "maker"},
        "verb": "query-state", "body": {"include": ["tools"]},
        "authority": {"basis": "role", "role": "verify", "oversees": "m1", "reserved": False},
        "grounding": None, "enforcement": None,
        "some_unknown_future_field": {"x": 1},  # MUST be ignored
    }
    assert schema.validate(wire) == []
    m = env.from_wire(wire)
    assert m.grounding is None and m.enforcement is None
    assert m.verb is Verb.QUERY_STATE


def test_round_trip_wire():
    comp = _party("comp1", "policy-compliance")
    maker = _party("m1", "maker")
    m = env.new_message(from_=comp, to=maker, verb=Verb.ISSUE_DIRECTIVE,
                        body=env.issue_directive_body("narrow scope", "constrain", "role-judgement"),
                        authority=_auth())
    m2 = env.from_wire(env.to_wire(m))
    assert m2.id == m.id
    assert m2.verb is Verb.ISSUE_DIRECTIVE
    assert m2.body["kind"] == "constrain"
    assert m2.from_.role == "policy-compliance"
