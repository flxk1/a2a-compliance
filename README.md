<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# a2a-compliance

**May a compliance team allow this maker action to take effect?**

Plan a governed maker action across the Loomground family, then control
the maker over an A2A protocol. Two profiles: a protocol floor and
a fail-closed Loomground compliance team.

## Problem

Multi-agent runs have makers and overseers. Steering a maker needs a channel, a resolved authority, and the boundary that maker itself declares.

## Install

```
pip install "git+https://github.com/flxk1/a2a-compliance.git"
```

Base install has zero dependencies. Extras: `.[schema]` (jsonschema>=4, referencing>=0.30), `.[manifest]` (PyYAML>=6), `.[crypto]` (cryptography>=41), `.[dev]` (all three plus pytest>=7).

## Usage

```python
from a2a_compliance import ComplianceAgent, ControlParticipant, FileInbox, GovernanceBlock, Roster
block = GovernanceBlock.from_manifest("tests/fixtures/maker_skill.md")
inbox = FileInbox("a2a-inbox")
comp = ComplianceAgent("comp-1", "policy-compliance", inbox, Roster(), {"maker-1": block})
maker = ControlParticipant("maker-1", inbox, compliance_actor="comp-1")
for kind in ("edit", "commit", "push"):
    comp.issue_directive("maker-1", "keep edits in module X", "constrain", target_kind=kind)
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

- compliance side: `ComplianceAgent.query_state | issue_directive | hold | resume | halt | collect_replies | ground_and_steer` → `DispatchResult`
- maker side: `ControlParticipant.checkpoint() → [Message]` · `should_continue()` · `is_held()`. Opt-in `a2a_compliance.harness.HarnessTransport` stops makers it spawned ([docs/transport.md](docs/transport.md))
- authority: `authorize(from_role, verb, maker_id, roster) → Authorization`; `halt` is reserved and dispatches on `confirm=True`
- boundary: `GovernanceBlock.from_manifest(path).rule(kind) → SteerRuling(STEER | ROUTE_HUMAN | REFUSE)`
- grounding: `ground(GroundingContext) → GroundingResult` over six value planes, advisory when absent · `accept_compiled_policy(payload)` ([docs/value-grounding.md](docs/value-grounding.md))
- team: `ComplianceTeam.plan(ControlRequest) → ControlPlan` · `assess(ControlRequest, GroundingResult)`. `TeamProfile.PROTOCOL` runs zero role steps and clears on the boundary alone; `TeamProfile.LOOMGROUND` routes to a human on at least a missing required capability, assessment, or reserved action. The plan cannot send, mutate, erase, certify or dispatch, and consumes capabilities instead of regrowing them; `ready` means ready to begin the host-orchestrated hand-offs, never ready to dispatch ([docs/compliance-team.md](docs/compliance-team.md))
- roles: `role_manifests()` loads eight packaged `a2a_compliance/roles/*.json`; every role sets `may_dispatch: false`
- lifecycle: `enforce_preview(plan, receipts) → EnforcementPreview` admits, holds, routes to a human, or refuses on role-owned, digest-bound receipts; `reconcile(plan, preview, control_receipt, receipts) → Reconciliation` certifies only a complete, admitted dispatch. Dispatch, enforcement, erasure and evidence writing stay host acts ([docs/lifecycle.md](docs/lifecycle.md))
- admission: `wire.admit(plan, stage_receipts, …) → AdmissionResult` returns ADMITTED, REVIEW_REQUIRED or REFUSED over stage receipts it verifies first; a prohibited or undeclared action is refused, a reserved action is admitted only with a human-approval receipt that verifies and is bound to the same action digest, and a plan that is only `ready` never admits. `wire.issue_permit(admission, …) → PermitIssueResult` signs a single-use `ExecutionPermit` for an admitted action alone
- execution: `wire.consume_and_execute(permit, tool=…, arguments=…, executor=…) → ExecutionResult` runs a host-supplied executor only against a permit it verifies, whose tool and arguments match what the permit bound, after atomically spending the permit's nonce, and records a signed `ToolReceipt`. A missing, tampered, replayed, expired, revoked or argument-mutated permit produces no effect
- assurance: `wire.reconcile(permit, tool_receipts, observed, …) → ReconciliationResult` compares receipt effects against a host-observed set and is not clean on any residual; `wire.certify(permit, tool_receipts, reconciliation, …) → CertificationResult` issues an `OversightCertificate` only when the permit verifies at an enforcement grade, the receipts bind the action, the reconciliation is clean, every blocking obligation carries a verified `ObligationDischargeReceipt`, every mandatory source is fresh, and the certifying identity differs from the issuer, the executors, the reconciler and the approver. `wire.audit_chain_verify(…) → ChainVerificationResult` detects removal, reorder or mutation of any object in a run's chain
- conformance: `wire.run_conformance(ports) → ConformanceReport` drives plan → admit → permit → execute → reconcile → certify through host-supplied ports and reports whether each guarantee fails closed. `wire.Profile` reports a deployment's grade as `advisory`, `mediated` or `platform`; `mediated` requires both the observed bypass rejection and the host's attestation that the tool has no path around the proxy, which the kit cannot observe itself
- wire: `envelope.to_wire` / `envelope.from_wire` against `schema/a2a-control-message.schema.json`

## Family

Runtime controls. `ComplianceTeam` assigns the 41 repositories to eight roles. Optional to both profiles; LOOMGROUND degrades an absent one to a human route. Consumed by [loomground-mcp](https://github.com/flxk1/loomground-mcp), serving `compliance-fleet`. Catalogue: [CATALOGUE.json](https://github.com/flxk1/loomground/blob/main/CATALOGUE.json).

## Status

301 tests · Python >=3.10 · latest tagged release 0.4.0

`main` carries the whole enforcement chain: admission over verified stage receipts, single-use signed execution permits, mediated execution in which a replayed, tampered, expired or revoked permit produces no effect, postflight reconciliation of observed effects against the permit, and an oversight certificate issued only when every check passes and the certifier is a distinct identity from the issuer, the executors, the reconciler and the approver. The 0.4.0 tag predates that chain, which is recorded under `Unreleased` in the [CHANGELOG](CHANGELOG.md).

Mediation reaches only effects routed through `wire.consume_and_execute`. Dispatch, enforcement, erasure and evidence writing stay host acts, and a maker holding another route to an effect is outside the control plane; `wire.Profile` grades that deployment `advisory` unless the host attests there is no path around the proxy.

## License

Apache-2.0 `LICENSES/Apache-2.0.txt` · `REUSE.toml`
