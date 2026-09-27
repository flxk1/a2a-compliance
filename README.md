<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# a2a-compliance

**May a compliance team allow this maker action to take effect?**

Plan a governed maker action across the Loomground family, then control the maker over an A2A protocol. Two profiles: a protocol floor and a fail-closed Loomground compliance team.

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
- maker side: `ControlParticipant.checkpoint() → [Message]` · `should_continue()` · `is_held()`. With a `trust_store` (authenticated mode), `checkpoint()` applies an envelope only if its signature verifies against a key bound to the sender's role, it has not expired, its `(sender, nonce)` is new to the `NonceStore` when one is injected, and `authorize()` allows the verb; any other envelope is never applied and is answered `ack{accepted: false}` with the reason, and without the `crypto` extra every envelope is rejected. Without a `trust_store` (bare mode) envelopes are unsigned and every honoured message is answered `mode: "advisory"`. Opt-in `a2a_compliance.harness.HarnessTransport` stops makers it spawned ([docs/transport.md](docs/transport.md))
- authority: `authorize(from_role, verb, maker_id, roster) → Authorization`; `halt` is reserved. In bare mode it dispatches on `confirm=True`, an advisory gate. A `ComplianceAgent` with a `trust_store` dispatches a halt only with a `HumanApprovalReceipt` that verifies, is bound to `envelope.halt_digest` for that halt, and is approved by a `human` identity other than the sender and the maker; `confirm=True` alone does not dispatch
- boundary: `GovernanceBlock.from_manifest(path).rule(kind) → SteerRuling(STEER | ROUTE_HUMAN | REFUSE)`
- grounding: `ground(GroundingContext) → GroundingResult` over six value planes, advisory when absent · `accept_compiled_policy(payload)` ([docs/value-grounding.md](docs/value-grounding.md))
- team: `ComplianceTeam.plan(ControlRequest) → ControlPlan` · `assess(ControlRequest, GroundingResult)`. `TeamProfile.PROTOCOL` runs zero role steps and clears on the boundary alone; `TeamProfile.LOOMGROUND` routes to a human on at least a missing required capability, assessment, or reserved action. The plan cannot send, mutate, erase, certify or dispatch, and consumes capabilities instead of regrowing them; `ready` means ready to begin the host-orchestrated hand-offs, never ready to dispatch ([docs/compliance-team.md](docs/compliance-team.md))
- roles: `role_manifests()` loads eight packaged `a2a_compliance/roles/*.json`; every role sets `may_dispatch: false`
- lifecycle: `enforce_preview(plan, receipts) → EnforcementPreview` admits, holds, routes to a human, or refuses on role-owned, digest-bound receipts; `reconcile(plan, preview, control_receipt, receipts) → Reconciliation` certifies only a complete, admitted dispatch. Dispatch, enforcement, erasure and evidence writing stay host acts ([docs/lifecycle.md](docs/lifecycle.md))
- admission: `wire.admit(plan, stage_receipts, …) → AdmissionResult` returns ADMITTED, REVIEW_REQUIRED or REFUSED over stage receipts it verifies first; a prohibited or undeclared action is refused, a reserved action is admitted only with a human-approval receipt that verifies and is bound to the same action digest, and a plan that is only `ready` never admits. Given a `SignedGovernanceBlock`, `admit` also requires the governance block in force to hash to the digest a policy author signed, that author to differ from the maker and to sign with a trust-store key bound to `GovernanceBlock` and the policy-author role, and then carries `governance_block_digest` into the permit. `wire.issue_permit(admission, …) → PermitIssueResult` signs a single-use `ExecutionPermit` for an admitted action alone
- execution: `wire.consume_and_execute(permit, tool=…, arguments=…, executor=…) → ExecutionResult` runs a host-supplied executor only against a permit it verifies, whose tool and arguments match what the permit bound, after atomically spending the permit's nonce, and records a signed `ToolReceipt`. A missing, tampered, replayed, expired, revoked or argument-mutated permit produces no effect. A permit issued with `aud` and `cnf` executes only for the executor `aud` names, presenting an Ed25519 proof of possession by the key `cnf.jkt` names over the permit's `subject_digest` and nonce; without it the permit produces no effect and its nonce stays unspent
- assurance: `wire.reconcile(permit, tool_receipts, observed, …) → ReconciliationResult` compares receipt effects against a host-observed set and is not clean on any residual; `wire.certify(permit, tool_receipts, reconciliation, …) → CertificationResult` issues an `OversightCertificate` only when the permit verifies at an enforcement grade, the receipts bind the action, the reconciliation is clean, every blocking obligation carries a verified `ObligationDischargeReceipt`, every mandatory source is fresh, and the certifying identity differs from the issuer, the executors, the reconciler and the approver. `wire.audit_chain_verify(…) → ChainVerificationResult` detects removal, reorder or mutation of any object in a run's chain
- conformance: `wire.run_conformance(ports) → ConformanceReport` drives plan → admit → permit → execute → reconcile → certify through host-supplied ports and reports whether each guarantee fails closed. `wire.Profile` reports a deployment's grade as `advisory`, `mediated` or `platform`; `mediated` requires both the observed bypass rejection and the host's attestation that the tool has no path around the proxy, which the kit cannot observe itself. Every scenario, including forged control sender, replayed resume, unapproved halt, tampered governance block, foreign executor and missing proof of possession, carries an OWASP Agentic AI Top 10 (2026) id in `ScenarioResult.asi`
- wire: `envelope.to_wire` / `envelope.from_wire` against `schema/a2a-control-message.schema.json`. A signed envelope adds `nonce`, `expires_at`, `key_id` and `signature` (`envelope.stamp_and_sign`); a bare envelope omits them. `FileInbox` creates its message files 0600

## Family

Runtime controls. `ComplianceTeam` assigns the 43 repositories to eight roles. Optional to both profiles; LOOMGROUND degrades an absent one to a human route. Consumed by [loomground-mcp](https://github.com/flxk1/loomground-mcp), serving `compliance-fleet`. Catalogue: [CATALOGUE.json](https://github.com/flxk1/loomground/blob/main/CATALOGUE.json).

## Status

369 tests · Python >=3.10 · latest tagged release 0.4.0

`main` carries the whole enforcement chain: admission over verified stage receipts, single-use signed execution permits, mediated execution in which a replayed, tampered, expired or revoked permit produces no effect, postflight reconciliation of observed effects against the permit, and an oversight certificate issued only when every check passes and the certifier is a distinct identity from the issuer, the executors, the reconciler and the approver. `main` also carries an authenticated control channel (signed, expiring envelopes with a replay-checked nonce, and a halt gated on a verified human-approval receipt), sender-constrained permits, and a governance block pinned by a distinct policy author's signature. Each is opt-in: a deployment that configures no trust store runs the control channel in bare mode, where every honoured message is advisory. The 0.4.0 tag predates that chain, which is recorded under `Unreleased` in the [CHANGELOG](CHANGELOG.md).

Mediation reaches only effects routed through `wire.consume_and_execute`. Dispatch, enforcement, erasure and evidence writing stay host acts, and a maker holding another route to an effect is outside the control plane; `wire.Profile` grades that deployment `advisory` unless the host attests there is no path around the proxy.

## License

Apache-2.0 `LICENSES/Apache-2.0.txt` · `REUSE.toml`
