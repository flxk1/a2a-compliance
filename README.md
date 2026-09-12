<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# a2a-compliance

**May a compliance agent direct this maker into that action?**

Control maker agents over an A2A protocol with role authority and optional Loomground value grounding.

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
- wire: `envelope.to_wire` / `envelope.from_wire` against `schema/a2a-control-message.schema.json`; `Verb`, `Message`, `Grounding`, `Enforcement` re-exported from `interfaces.a2a_control`

## Family

Runtime controls. Consumes nothing at runtime: `dependencies = []` in `pyproject.toml`, with `jsonschema` and `PyYAML` as optional extras. Each Loomground value plane is optional here and degrades instead of breaking — `available()` probes with `find_spec`, and an absent plane falls back to the advisory reading for that one dimension. External enforcement is a declared, host-neutral seam: `enforcement` serialises as JSON `null` until a host supplies an adapter. Consumed by ctrl-plane hosts as the `compliance-fleet` skill, and paired with the maker's own `skill-governance-block`. Design: [docs/spec.md](docs/spec.md). Modes, axes and invariants: [docs/modes.md](docs/modes.md).

## Status

0.1.0 · 54 tests · Python >=3.10 · zero runtime dependencies · external enforcement is design only

## License

Apache-2.0 `LICENSES/Apache-2.0.txt` · `REUSE.toml`
