"""The compile->ground chain, end to end (SPEC §4, policy-compiler seam).

policy-compiler compiles a small prose policy into O/P/F norms; `to_grounding_seam()`
emits the payload the fleet accepts as its norm base; the fleet grounds a maker's
proposed action against it via the deontic plane. Runs in a subprocess so the parent
process stays loomground-free. Skipped only if the policy-compiler package is absent."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parent / "_ground_probe.py"
PROJECTS = Path(__file__).resolve().parents[2]
POLICY_COMPILER = PROJECTS / "policy-compiler" / "policy_compiler" / "__init__.py"

pytestmark = pytest.mark.skipif(
    not POLICY_COMPILER.exists(), reason="policy-compiler not present in this checkout"
)

POLICY = (
    "The maker must not delete the audit trail. "
    "The maker must run the tests before committing."
)


def run_probe(spec: dict, tmp_path) -> dict:
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(PROBE), str(spec_file)], capture_output=True, text=True
    )
    assert proc.returncode == 0, f"probe failed:\nSTDOUT{proc.stdout}\nSTDERR{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_compiled_prohibition_grounds_to_a_hold(tmp_path):
    # Compile the policy, then ground a maker action that violates its prohibition.
    out = run_probe({
        "add_src": True,
        "compile_policy": POLICY,
        "context": {
            "maker_id": "maker-1",
            "proposed_action": {"bearer": "maker", "action": "delete the audit trail"},
        },
    }, tmp_path)

    # The seam carried a real compiled prohibition into the fleet.
    assert any(n["operator"] == "F" and n["action"] == "delete the audit trail"
               for n in out["policy_norms"])
    # ... which the deontic plane turned into a grounded hold.
    assert out["recommended_action"] == "hold"
    deontic = next(f for f in out["findings"] if f["dimension"] == "deontic")
    assert deontic["verdict"] == "not_satisfied"
    assert deontic["provenance"] == "grounded-via-deontic"


def test_compiled_policy_permits_an_unforbidden_action(tmp_path):
    out = run_probe({
        "add_src": True,
        "compile_policy": POLICY,
        "context": {
            "maker_id": "maker-1",
            "proposed_action": {"bearer": "maker", "action": "read the brief"},
        },
    }, tmp_path)
    # No prohibition on this action -> deontic is satisfied, no hold from deontic.
    deontic = next(f for f in out["findings"] if f["dimension"] == "deontic")
    assert deontic["verdict"] == "satisfied"
    assert out["recommended_action"] in ("no-steer", "route-human")  # no hold/steer
    assert out["recommended_action"] != "hold"
