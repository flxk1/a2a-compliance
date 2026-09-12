"""Grounded mode (SPEC §2 mode (b), §4): the fleet draws its steer/hold/escalate from
the loomground value graph. Each case runs in a SUBPROCESS (`_ground_probe.py`) so the
parent pytest process stays loomground-free and the Phase-1 invariant test stays honest.

`add_src=True` makes ALL SIX planes importable from their on-disk src (full real-consume);
the specific cases prove the mapping: prohibition -> hold, mandate divergence -> steer,
escalation ceiling -> route-human, gamed proxy -> hold, weak evidence -> route-human,
clean -> no-steer. A partial case (natural env, some planes absent) proves per-dimension
degradation with honest provenance."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parent / "_ground_probe.py"


def run_probe(spec: dict, tmp_path) -> dict:
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(PROBE), str(spec_file)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"probe failed:\nSTDOUT{proc.stdout}\nSTDERR{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


FORBIDDEN_POLICY = {
    "protocol": "policy-compiler/0.1",
    "norms": [{"operator": "F", "bearer": "maker", "action": "delete the audit trail"}],
}


def test_prohibition_collision_maps_to_hold(tmp_path):
    out = run_probe({
        "add_src": True,
        "context": {
            "maker_id": "maker-1",
            "proposed_action": {"bearer": "maker", "action": "delete the audit trail"},
            "policy": FORBIDDEN_POLICY,
        },
    }, tmp_path)
    assert out["recommended_action"] == "hold"
    assert out["grounding_verdict"] == "not_satisfied"
    deontic = next(f for f in out["findings"] if f["dimension"] == "deontic")
    assert deontic["verdict"] == "not_satisfied"
    assert deontic["provenance"] == "grounded-via-deontic"


def test_mandate_divergence_maps_to_steer(tmp_path):
    out = run_probe({
        "add_src": True,
        "context": {
            "maker_id": "maker-1",
            "mandate": {"purposes": ["review", "draft"], "evidence": "engagement-letter"},
            "trajectory": [
                {"step": "read the brief", "serves": ["review"]},
                {"step": "place an order", "serves": ["procure"]},
            ],
        },
    }, tmp_path)
    assert out["recommended_action"] == "steer"
    mandate = next(f for f in out["findings"] if f["dimension"] == "mandate")
    assert mandate["verdict"] == "not_satisfied"
    assert mandate["provenance"] == "grounded-via-mandate"


def test_escalation_ceiling_maps_to_route_human(tmp_path):
    out = run_probe({
        "add_src": True,
        "context": {
            "maker_id": "maker-1",
            "autonomy": {
                "requested": "L3", "delegated": "L3",
                "factors": [{"name": "irreversible", "ceiling": "L1", "why": "destructive"}],
            },
        },
    }, tmp_path)
    assert out["recommended_action"] == "route-human"
    esc = next(f for f in out["findings"] if f["dimension"] == "escalation")
    assert esc["verdict"] == "not_satisfied"
    assert esc["provenance"] == "grounded-via-escalation"


def test_gamed_proxy_maps_to_hold(tmp_path):
    out = run_probe({
        "add_src": True,
        "context": {
            "maker_id": "maker-1",
            "proxies": [{
                "metric": "tickets_closed", "stands_for": "problems_solved",
                "metric_movement": "improved", "value_movement": "worsened",
            }],
        },
    }, tmp_path)
    assert out["recommended_action"] == "hold"
    proxy = next(f for f in out["findings"] if f["dimension"] == "proxy")
    assert proxy["verdict"] == "not_satisfied"


def test_weak_evidence_maps_to_route_human(tmp_path):
    out = run_probe({
        "add_src": True,
        "context": {
            "maker_id": "maker-1",
            "claims": [{"claim": "tests pass", "falsifiability": "self_report"}],
        },
    }, tmp_path)
    assert out["recommended_action"] == "route-human"
    fal = next(f for f in out["findings"] if f["dimension"] == "falsifiability")
    assert fal["verdict"] == "open"
    assert fal["applicable"] is True


def test_clean_run_maps_to_no_steer(tmp_path):
    out = run_probe({
        "add_src": True,
        "context": {
            "maker_id": "maker-1",
            "mandate": {"purposes": ["review"], "evidence": "engagement-letter"},
            "trajectory": [{"step": "read the brief", "serves": ["review"]}],
            "claims": [{"claim": "tests pass", "falsifiability": "verified_outcome"}],
            "autonomy": {
                "requested": "L1", "delegated": "L3",
                "factors": [{"name": "reversible", "ceiling": "L3", "why": "safe"}],
            },
        },
    }, tmp_path)
    assert out["recommended_action"] == "no-steer"
    assert out["grounding_verdict"] == "satisfied"


def test_all_six_planes_grounded_with_honest_provenance(tmp_path):
    out = run_probe({
        "add_src": True,
        "context": {
            "maker_id": "maker-1",
            "proposed_action": {"bearer": "maker", "action": "ship it"},
            "policy": {"protocol": "policy-compiler/0.1",
                       "norms": [{"operator": "P", "bearer": "maker", "action": "ship it"}]},
            "policy_text": "The maker must not delete the audit trail.",
            "mandate": {"purposes": ["review"], "evidence": "engagement-letter"},
            "trajectory": [{"step": "read", "serves": ["review"]}],
            "claims": [{"claim": "done", "falsifiability": "verified_outcome"}],
            "autonomy": {"requested": "L1", "delegated": "L2",
                         "factors": [{"name": "x", "ceiling": "L2"}]},
            "proxies": [{"metric": "m", "stands_for": "v",
                         "metric_movement": "improved", "value_movement": "improved"}],
        },
    }, tmp_path)
    prov = out["provenance"]
    assert all(prov[d] == f"grounded-via-{d}" for d in (
        "deontic", "norm", "mandate", "escalation", "proxy", "falsifiability"))
    assert out["any_grounded"] is True


@pytest.mark.skipif(importlib.util.find_spec("deontic") is None,
                    reason="this case reads an INSTALLED deontic plane (CI installs it); "
                           "`add_src` is what a bare checkout uses")
def test_partial_grounding_degrades_absent_planes(tmp_path):
    # Natural env: deontic/norm/proxy installed; mandate/escalation/falsifiability not.
    # A prohibition collision still drives a real hold off the present deontic plane,
    # while the absent planes honestly read advisory-absent.
    out = run_probe({
        "add_src": False,
        "context": {
            "maker_id": "maker-1",
            "proposed_action": {"bearer": "maker", "action": "delete the audit trail"},
            "policy": FORBIDDEN_POLICY,
        },
    }, tmp_path)
    assert out["recommended_action"] == "hold"           # driven by the present deontic plane
    prov = out["provenance"]
    assert prov["deontic"] == "grounded-via-deontic"
    for absent in ("mandate", "escalation", "falsifiability"):
        assert prov[absent] == "advisory-absent"
    # partial grounding is still grounding (not bare/null)
    assert out["grounding_verdict"] is not None
    assert out["any_grounded"] is True
