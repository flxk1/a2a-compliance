"""The Phase-1 path imports no Loomground module or host enforcer.

Grounding and enforcement stay None through a full bare-mode flow.
"""

import sys

import a2a_compliance  # noqa: F401  (import the whole package)
from a2a_compliance import ComplianceAgent, ControlParticipant, FileInbox, Roster


def _loomground_modules():
    bad = []
    for name in list(sys.modules):
        head = name.split(".", 1)[0]
        if head.startswith("loomground_") or head == "loomground":
            bad.append(name)
    return bad


def test_no_loomground_imported_by_package():
    assert _loomground_modules() == []


def test_full_flow_imports_no_enrichment(tmp_path):
    inbox = FileInbox(tmp_path / "ib")
    comp = ComplianceAgent(session_id="c", role="verify", inbox=inbox, roster=Roster())
    maker = ControlParticipant(session_id="m", inbox=inbox, compliance_actor="c",
                               state_provider=lambda inc: {})
    d = comp.issue_directive("m", "steer", "correct")
    assert d.dispatched
    resp = maker.checkpoint()
    assert resp[0].grounding is None
    assert resp[0].enforcement is None
    assert d.message.grounding is None
    assert d.message.enforcement is None
    assert _loomground_modules() == []
