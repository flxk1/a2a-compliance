---
name: compliance-fleet
description: >-
  Control a fleet of maker agents and keep them aligned to the operator's
  values, over an A2A (agent-to-agent) control channel: query a maker's state,
  issue a directive, hold, resume, or halt (compliance -> maker); receive
  report-state, ack, escalate (maker -> compliance). Works fully with ZERO
  loomground and ZERO RVND: in bare mode the steering criteria are the ctrl
  compliance ROLE's advisory judgement and authority is role-based from the
  team-charter roster. loomground is an OPTIONAL, UNIVERSAL enrichment: when a
  value plane is present the steer criteria are DRAWN FROM the grounded value
  graph (O/P/F deontic norms, mandate, escalation, proxy, falsifiability) behind
  per-plane flags, degrading to advisory per dimension when absent. RVND is an
  OPTIONAL enforcement skin behind an adapter that no-ops when absent — it adds
  a permit/hold/deny verdict + signed chain to a directive; its absence never
  blocks an op. The A2A directive is the live steer primitive the ctrl-desk
  steer/hold op needs, and it steers a maker WITHIN the boundary the maker
  declares in its skill-governance block. Triggers on "control my agents",
  "keep the makers aligned", "steer/hold/halt this maker", "watch the fleet for
  value drift", "issue a compliance directive". Implemented in the a2a_compliance package (bare control + value grounding); SPEC.md is the design reference.
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
    - require_rvnd_on_default_path
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

The A2A control-message contract (both directions, all three modes), the maker
control-participant contract, the value-plane consumption seam, the
governance-block seam, the authority model, and the plane manifest are defined in
[`../../SPEC.md`](../../SPEC.md) and implemented in the `a2a_compliance` package:
the control channel and cooperative-poll participant, role-based authority from
the team-charter roster, the governance-block reader, and the value grounding —
`planes.py` consumes the six loomground value planes behind per-plane
availability, and `grounding.py` folds their verdicts into the envelope
`grounding` block and the steer / hold / escalate decision. RVND enforcement
(Phase 3) is a declared, flag-gated seam.

## Verbs (see SPEC §3)

- compliance -> maker: `query-state`, `issue-directive`, `hold`, `resume`,
  `halt`.
- maker -> compliance: `report-state`, `ack`, `escalate`.

Every verb is total in bare mode (no loomground, no RVND). `grounding` and
`enforcement` are additive envelope planes — `null` is a valid state, never a
failure.

## Governance-block notes

- `grade: L1` default; `halt` is `L2` (it stops an autonomous actor,
  irreversible).
- `halt`/`issue_directive` are `reserved` to the workspace owner — surfaced to
  the human in every mode (a fleet-level reserved act, per the ctrl oversight
  rules), regardless of whether loomground/RVND is present.
- The `prohibited`/`obligations` encode both overriding invariants: no
  loomground/RVND on the default path; a directive stays within the maker's own
  declared governance boundary; self-report is never fused with witnessed;
  `OPEN` escalates and never counts as satisfied; a principled maker refusal is
  never auto-overridden.
- This skill CONSUMES the maker's `skill-governance-block`; it does not redefine
  it. Validate this block against
  `skill-governance-block/schema/governance-block.schema.json` before any
  publication; the block must also compile to a well-formed loomground `.lg`
  patch.
