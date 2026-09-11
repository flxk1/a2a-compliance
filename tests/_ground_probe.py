"""Out-of-process grounding probe (NOT a test module — underscore-prefixed so pytest
does not collect it).

The grounded/partial Phase-2 tests run the fleet HERE, in a fresh interpreter, so the
parent pytest process stays free of any `loomground_*` import — keeping the Phase-1
invariant test (`test_no_enrichment_imports`) honest and green. This subprocess is the
one place loomground is actually imported and consumed.

Usage: ``python _ground_probe.py <spec.json>`` -> prints one JSON result line.

Spec keys (all optional):
  add_src        bool  — add the on-disk src of the not-installed planes to sys.path,
                         so ALL SIX planes are importable (full real-consume demo).
  disable        str   — value for A2A_DISABLE_PLANES ("all" or a comma list).
  compile_policy str   — compile this prose via policy-compiler; use its
                         to_grounding_seam() as the policy (the compile->ground chain).
  context        dict  — GroundingContext fields (proposed_action, policy_text,
                         mandate, trajectory, claims, autonomy, proxies, maker_id).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECTS = Path(__file__).resolve().parents[2]
REPO = Path(__file__).resolve().parents[1]


def main() -> None:
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

    # Make the a2a-compliance repo importable.
    sys.path.insert(0, str(REPO))

    # Optionally make the not-installed planes importable from their on-disk src.
    if spec.get("add_src"):
        for plane in ("mandate", "escalation", "falsifiability"):
            src = PROJECTS / "loomground-repos" / f"loomground-{plane}" / "src"
            if src.is_dir():
                sys.path.insert(0, str(src))

    if spec.get("disable"):
        os.environ["A2A_DISABLE_PLANES"] = spec["disable"]

    from a2a_compliance import GroundingContext, ground, accept_compiled_policy

    ctx_kwargs = dict(spec.get("context") or {})

    if spec.get("compile_policy"):
        sys.path.insert(0, str(PROJECTS / "policy-compiler"))
        from policy_compiler import compile as pc_compile

        draft = pc_compile(spec["compile_policy"])
        ctx_kwargs["policy"] = accept_compiled_policy(draft.to_grounding_seam())

    ctx = GroundingContext(**ctx_kwargs)
    result = ground(ctx)

    out = {
        "recommended_action": result.recommended_action,
        "reason": result.reason,
        "grounding_verdict": (result.grounding.verdict.value if result.grounding else None),
        "any_grounded": result.any_grounded,
        "provenance": result.provenance(),
        "findings": [
            {
                "dimension": f.dimension,
                "verdict": f.verdict.value,
                "grounded": f.grounded,
                "applicable": f.applicable,
                "provenance": f.provenance,
                "reason": f.reason,
            }
            for f in result.findings
        ],
    }
    if spec.get("compile_policy"):
        out["policy_mode"] = ctx_kwargs["policy"]["mode"]
        out["policy_norms"] = [
            {"operator": n["operator"], "bearer": n["bearer"], "action": n["action"]}
            for n in ctx_kwargs["policy"]["norms"]
        ]
    print(json.dumps(out))


if __name__ == "__main__":
    main()
