<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# a2a-compliance

**May a compliance team allow this maker action to take effect?**

Plan a governed maker action across the complete Loomground family, then control
the maker over an A2A protocol. The package has two explicit profiles: a
dependency-free protocol floor and a fail-closed Loomground compliance team.

## Problem

Multi-agent runs have makers and overseers. Steering a maker needs a channel, a resolved authority, and the boundary that maker itself declares.

## Install

```
pip install "git+https://github.com/flxk1/a2a-compliance.git"
```

Base install has zero dependencies. Extras: `.[schema]` (jsonschema>=4), `.[manifest]` (PyYAML>=6), `.[dev]` (both plus pytest>=7).

## Usage

```python
from a2a_compliance import ComplianceAgent, ControlParticipant, FileInbox, GovernanceBlock, Roster
block = GovernanceBlock.from_manifest("tests/fixtures/maker_skill.md")
inbox = FileInbox("/tmp/a2a")
comp = ComplianceAgent("comp-1", "policy-compliance", inbox, Roster(), {"maker-1": block})
maker = ControlParticipant("maker-1", inbox, compliance_actor="comp-1")
comp.issue_directive("maker-1", "keep edits in module X", "constrain", target_kind="edit")
maker.checkpoint()
```

## Example

```
in : tests/fixtures/maker_skill.md  actions[edit,read,run-tests] reserved[commit] prohibited[key-ops,push]
     comp-1 (policy-compliance) directs maker-1 toward edit, commit, push
out: edit   decision=steer        dispatched=True  verb=issue-directive
     commit decision=route-human  dispatched=False reserved_by=workspace_owner
     push   decision=refuse       dispatched=False
     maker-1 checkpoint -> ack accepted=True note="applied directive kind='constrain'"
```

## Interface

- compliance side: `ComplianceAgent.query_state | issue_directive | hold | resume | halt | collect_replies | ground_and_steer` → `DispatchResult(dispatched, authorization, message, ruling, surfaced_to_human, denied_reason, grounding_result)`
- maker side: `ControlParticipant.checkpoint() → [Message]` · `should_continue()` · `is_held()`; delivery is cooperative — a maker that never checkpoints is unsteerable ([docs/transport.md](docs/transport.md))
- authority: `authorize(from_role, verb, maker_id, roster) → Authorization` · `Roster` · `COMPLIANCE_ROLES` · `MAKER_ROLES`; `halt` is reserved and dispatches on `confirm=True`
- boundary: `GovernanceBlock.from_manifest(path).rule(kind) → SteerRuling(SteerDecision.STEER | ROUTE_HUMAN | REFUSE)`
- grounding: `ground(GroundingContext) → GroundingResult` · `ALL_PLANES` · `available(plane)` · `accept_compiled_policy(payload)` ([docs/value-grounding.md](docs/value-grounding.md))
- team: `ComplianceTeam.plan(ControlRequest) → ControlPlan` and
  `ComplianceTeam.assess(ControlRequest, GroundingResult) → ControlPlan`. The
  plan assigns all 41 public family repositories to eight roles and names the
  tools, skills, contracts and distributions each role consumes. It performs no
  dispatch or enforcement ([docs/compliance-team.md](docs/compliance-team.md)).
- roles: eight packaged contracts in `a2a_compliance/roles/*.json`, validated by
  `schema/compliance-role.schema.json`; each fixes identity, inputs, outputs,
  allowed consumed capabilities, prohibited effects and hand-offs.
- lifecycle: `enforce_preview(ControlPlan, [StageReceipt]) → EnforcementPreview`
  and `reconcile(ControlPlan, EnforcementPreview, ControlReceipt,
  [StageReceipt]) → Reconciliation`. Receipts are role-checked and bound to the
  proposed action digest. Preview and reconciliation never dispatch or perform
  the underlying checks ([docs/lifecycle.md](docs/lifecycle.md)).
- wire: `envelope.to_wire` / `envelope.from_wire` against `schema/a2a-control-message.schema.json`; `Verb`, `Message`, `Grounding`, `Enforcement` re-exported from `interfaces.a2a_control`

## Profiles

- `protocol`: the existing zero-dependency A2A channel and role-authority floor.
- `loomground`: the compliance-team plan. Required family capabilities must be
  present and a grounded assessment must exist; otherwise the plan routes to a
  human. The module consumes published capabilities and never regrows their
  implementation.

External enforcement remains a host act. A `ControlPlan` is inert: it cannot
send, mutate, erase, certify or dispatch anything.

## Status

0.1.0 · 74 tests · Python >=3.10 · zero runtime dependencies · enforcement preview only

## License

Apache-2.0 `LICENSES/Apache-2.0.txt` · `REUSE.toml`
