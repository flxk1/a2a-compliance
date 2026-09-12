<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Compliance team

`a2a_compliance.team` is the orchestration boundary for the full Loomground
profile. It consumes the family's published tools, skills and contracts. It does
not duplicate their implementations and it does not perform host effects.

The eight roles are:

1. `conductor` — governance language, workspace/vertical boundary, skill
   governance and distribution surfaces.
2. `evidence-grounder` — Ingest and Versum.
3. `policy-compiler` — written policy to checked executable norms.
4. `language-panel` — Factual, Epistemic, Deontic, Topos, Norm and the Legal
   contract.
5. `decision-verifier` — Solver evaluation and independent verification.
6. `oversight-assessor` — Brief, Collapse, Escalation, Falsifiability, Mandate,
   Proxy and the Oversight Ladder.
7. `runtime-controller` — Lane, Lock, Drift, Erasure and Privacy Shield.
8. `assurance-recorder` — certification, 5d-nd, oversight, posture, effects,
   freshness, obligation discharge, audit chain and evidence package.

Together with `a2a-compliance` itself, the manifest assigns all 41 public family
repositories exactly once. Repository ownership and capability invocation are
separate: a repository can contribute a callable tool, an installable skill, a
data/spec contract, or a distribution surface.

## Fail-closed planning

`ComplianceTeam.plan()` returns an inert `ControlPlan`.

- A prohibited or undeclared maker action is `refuse`.
- A reserved action is `route-human`.
- In the `loomground` profile, a missing required tool or contract is
  `route-human`.
- A complete inventory without a supplied grounded assessment is still
  `route-human`.
- Supporting skills and distributions are reported but do not masquerade as
  hard runtime dependencies.
- Only the dependency-free `protocol` profile may produce a role-advisory plan
  without family capabilities.

`ready` means that the host may begin the named orchestration hand-offs. It is
not a permit, not proof that those capabilities succeeded, and never means
ready-to-dispatch.

The host may execute a plan only after resolving these gates. Tool execution,
human approval, maker dispatch, enforcement, erasure and evidence writing remain
explicit host responsibilities.

## Consumption order

The intended orchestration is:

`evidence → policy/languages → solver → oversight → A2A decision → runtime controls → host dispatch → assurance/reconciliation`

This is a hand-off graph, not a bundled implementation. Each arrow passes
structured output from one existing capability to the next.
