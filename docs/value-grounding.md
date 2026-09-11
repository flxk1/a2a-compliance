<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Value grounding — steer/hold/escalate drawn from the value graph

Moved out of the README under the family README canon. Design: [`../SPEC.md`](../SPEC.md) §4.

When a loomground value plane is present, a compliance agent derives its criterion
from the grounded value graph instead of the role's advisory judgement. The seam is
`a2a_compliance.planes` (per-plane consumption) and `a2a_compliance.grounding` (the
derivation and the decision), reached from the send side via
`ComplianceAgent.ground_and_steer(maker, context)`.

Each of the six planes is consumed as a general capability behind an availability
probe. `planes.available(name)` uses `importlib.util.find_spec` — it does not import
the plane, so the bare path stays loomground-free; the real plane import happens only
inside `planes.assess`, when the plane is present and actually consumed. An absent
plane (or one that raises) degrades that one dimension to the advisory reading with
honest provenance (`advisory-absent`); every other dimension is unaffected. With no
plane present, `grounding` is `null` — exactly the bare behaviour.
`A2A_DISABLE_PLANES` (`"all"` or a comma list) forces a plane "absent" without
uninstalling it.

| plane | package | grounded criterion |
|---|---|---|
| deontic | `deontic` | the maker's proposed action collides with a policy prohibition (O-vs-F clash) |
| norm | `loomground_norm` | prose policy → extracted O/P/F duties; does the action match one? |
| mandate | `loomground_mandate` | does the maker's trajectory serve the purpose it was given? |
| escalation | `loomground_escalation` | requested autonomy vs the ceiling the factors leave |
| proxy | `loomground_proxy` | Goodhart: is a proxy metric gamed (up while its value fell)? |
| falsifiability | `loomground_falsifiability` | does the maker's evidence clear the support floor? |

Each returns the shared solver `Verdict` (SATISFIED / NOT_SATISFIED / OPEN). The
findings fold into the envelope's `grounding` block (weakest-link, OPEN-dominant) and
map to a control action:

| grounded finding | control action |
|---|---|
| prohibition collision (deontic) · gamed proxy | **hold** |
| over the escalation ceiling | **route-human** (reserved) |
| mandate divergence · norm breach | **steer** (`issue-directive`, in-boundary) |
| any remaining applicable **OPEN** | **route-human** (OPEN is never a silent pass) |
| all satisfied | **no-steer** |

A directive may be partly grounded — some dimensions grounded, others advisory — and
the envelope carries each dimension's own provenance
(`GroundingResult.provenance()`).

## The compile → ground handoff

`policy-compiler` (https://github.com/flxk1/policy-compiler) compiles a written
policy into O/P/F norms and emits them with `CompiledPolicy.to_grounding_seam()`. The
fleet accepts that payload as its norm base (`accept_compiled_policy`) and grounds a
maker's proposed action against the compiled prohibitions/obligations via the deontic
plane — one chain from policy prose to a grounded hold. The two compile-to-ground
tests self-skip when `policy-compiler` is absent.

## Running the grounded tests

```bash
pip install -e ".[dev]"
pytest -q
```

The grounded tests run the fleet in a subprocess (`tests/_ground_probe.py`), so the
parent test process imports no loomground module and the bare-path invariant stays
honest. They consume whichever planes are installed; three planes (mandate,
escalation, falsifiability) are read from their on-disk `src` in a sibling
`loomground-repos/` checkout, per the pins in `.github/workflows/ci.yml`. Those
subprocess tests fail when neither the installed package nor the sibling checkout is
reachable.
