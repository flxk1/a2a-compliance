---
name: compliance-fleet
description: >-
  Compliance agents steer maker agents over an agent-to-agent control channel, keeping them aligned to the
  operator's values: query a maker's state, issue a directive, hold, resume or halt; receive report-state,
  ack and escalate back. Authority is role-based, and a directive stays within the boundary that maker
  declares in its own governance block. Works in bare mode with zero Loomground and zero external enforcement, where the
  steering criterion is the compliance role's advisory judgement. Loomground is optional enrichment — where
  a value plane is present the criterion is drawn from the grounded value graph, degrading to advisory per
  dimension when that plane is absent. External enforcement is an optional adapter that adds a verdict and a signed
  chain to a directive. Triggers on "control my agents", "keep the makers aligned", "steer/hold/halt this
  maker", "watch the fleet for value drift", "issue a compliance directive".
allowed-tools: a2a_ground
governance:
  grade: L1
  actions:
    - { kind: query_state, risk: low }
    - { kind: issue_directive, risk: medium }
    - { kind: hold, risk: medium }
    - { kind: resume, risk: medium }
    - { kind: halt, risk: high, grade: L2 }
  reserved:
    - { kind: halt, by: workspace_owner }
    - { kind: issue_directive, by: workspace_owner }
  prohibited:
    - direct_maker_into_its_prohibited_kind
    - steer_outside_maker_declared_boundary
    - render_self_report_as_witnessed
    - require_loomground_on_default_path
    - require_external_enforcement_on_default_path
    - auto_override_a_principled_maker_refusal
  obligations:
    - authority_resolved_role_first
    - directive_within_declared_governance_block
    - grounding_null_when_value_plane_absent
    - tiers_never_fused
    - reserved_acts_surfaced_to_human_in_every_mode
    - open_verdict_escalates_never_counts_satisfied
  redress:
    - { kind: recorded_override, by: workspace_owner, overturn: true }
  budget: { usd: 1, iters: 30 }
  on-boundary: report-not-repair
---

# compliance-fleet

Primary path: call `a2a_ground` with the maker state and the requested value
planes. It returns the grounded/advisory findings and the bounded action. Message
dispatch remains a host act: the skill must surface reserved directives instead
of sending them through an undeclared channel.

The A2A control-message contract (both directions, all three modes), the maker
control-participant contract, the value-plane consumption seam, the
governance-block seam, the authority model, and the plane manifest are defined in
[`../../SPEC.md`](../../SPEC.md) and implemented in the `a2a_compliance` package:
the control channel and cooperative-poll participant, role-based authority from
the team-charter roster, the governance-block reader, and the value grounding —
`planes.py` consumes the six loomground value planes behind per-plane
availability, and `grounding.py` folds their verdicts into the envelope
`grounding` block and the steer / hold / escalate decision. External enforcement
(Phase 3) is a declared, flag-gated seam.

## Verbs (see SPEC §3)

- compliance -> maker: `query-state`, `issue-directive`, `hold`, `resume`,
  `halt`.
- maker -> compliance: `report-state`, `ack`, `escalate`.

Every verb is total in bare mode (no loomground, no external enforcement). `grounding` and
`enforcement` are additive envelope planes — `null` is a valid state, never a
failure.

## Governance-block notes

- `grade: L1` default; `halt` is `L2` (it stops an autonomous actor,
  irreversible).
- `halt`/`issue_directive` are `reserved` to the workspace owner — surfaced to
  the human in every mode (a fleet-level reserved act, per the ctrl oversight
  rules), regardless of whether loomground/external enforcement is present.
- The `prohibited`/`obligations` encode both overriding invariants: no
  loomground/external enforcement on the default path; a directive stays within the maker's own
  declared governance boundary; self-report is never fused with witnessed;
  `OPEN` escalates and never counts as satisfied; a principled maker refusal is
  never auto-overridden.
- This skill CONSUMES the maker's `skill-governance-block`; it does not redefine
  it. Validate this block against
  `skill-governance-block/schema/governance-block.schema.json` before any
  publication; the block must also compile to a well-formed loomground `.lg`
  patch.
