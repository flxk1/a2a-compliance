# a2a-compliance — compliance agents control makers

*A loomground fleet to control your agents and protect your values.*

An **A2A (agent-to-agent) control protocol** plus a **compliance-fleet
contract**: a fleet of **compliance agents** watches the **maker** agents and
keeps them aligned to the operator's **values**, steering them over a control
channel — `query-state`, `issue-directive`, `hold`, `resume`, `halt` (compliance
→ maker); `report-state`, `ack`, `escalate` (maker → compliance).

## Two overriding invariants

1. **Everything works WITHOUT RVND.** RVND is *optional enrichment* (an enforced
   permit/hold/deny verdict + a signed-chain audit) — never a dependency.
2. **Every loomground repo is OPTIONAL and UNIVERSAL.** The fleet does not
   hard-depend on any loomground repo; it works without them and *enriches* when
   one is present (graceful degradation), consuming each as a general,
   host-agnostic capability.

The fleet's **only hard footing** is its own **ctrl substrate**: the A2A control
channel + the role-based authority of the ctrl team-charter roster. Loomground
value-grounding and RVND enforcement are BOTH optional planes on top.

Grounding is **optional-at-runtime but canonical-when-used**: when the fleet
grounds its criteria it uses loomground and never builds a parallel grounding
layer; when loomground is absent it degrades to role-based / advisory control —
it does not crash.

## Two axes, kept separate

```
        compliance-fleet skill  (orchestration plane — this repo)
   query-state · issue-directive · hold · resume · halt   (compliance -> maker)
        report-state · ack · escalate                     (maker -> compliance)
        ┌───────────────────────┴───────────────────────┐
   AXIS A — the CHANNEL (A2A)               AXIS B — AUTHORITY (who may steer whom)
   ctrl / orchestration plane               role-based (team-charter) by default
   complements MCP (MCP = agent<->tools;    RVND-gated + chained when RVND present
   A2A = agent<->agent)
        ┌───────────────┴────────────────┐
   HARD FOOTING (bare)              OPTIONAL enrichment (both degrade, never crash)
   A2A channel + team-charter       loomground value graph (per-plane flags):
   role roster                      deontic·norm·mandate·escalation·proxy·falsifiability
                                    RVND adapter (no-op when absent):
                                    permit/hold/deny + signed chain
```

## Three modes

- **(a) bare** — no loomground, no RVND. Steer criteria = the compliance role's
  advisory judgement; authority = role-based. **Fully functional alone.**
- **(b) +loomground** — steer criteria are *drawn from* the grounded value graph
  (O/P/F deontic norms, mandate, escalation, proxy, falsifiability), per-plane,
  behind flags; advisory fallback per dimension when a plane is absent.
- **(c) +RVND** — the directive is additionally enforced (permit/hold/deny) and
  written to the signed chain.

## Seams

- **skill-governance-block** — A2A steers a maker *within* the boundary the maker
  declares in its own governance block. This repo consumes that neutral spec; it
  does not redefine it.
- **ctrl-desk** — the desk's `steer`/`hold`/`launch` ops (today: recorded
  intent) emit A2A directives the maker honours. The desk is the human injection
  point.

## Status — Phase 1 is runnable

**Phase 1 (bare A2A + role authority) is built and tested; Phases 2–3 are still
design.** The `a2a_compliance` package implements the bare control channel end to
end — with **zero loomground and zero RVND**. See [`SPEC.md`](SPEC.md) for the
full design (all three modes, the value-plane seam with its honest
REAL-CONSUME/STUB read, the RVND adapter, phasing, and open gaps).

What Phase 1 gives you (SPEC §12.1):

1. **The A2A control-message contract** — envelope + all eight verbs, validated
   against `schema/a2a-control-message.schema.json`. `grounding` and
   `enforcement` are always `null`; a receiver treats `null` as a valid state,
   never a failure, and ignores unknown fields (`a2a_compliance.envelope`,
   `a2a_compliance.schema`).
2. **Role-based authority** from the ctrl team-charter roster — a compliance role
   (`policy-compliance`/`grounding`/`verify`) may steer a maker it oversees; an
   out-of-role sender is denied; `halt` is authorized-but-reserved
   (`a2a_compliance.authority`).
3. **The governance-block reader** — reads a maker's declared
   `skill-governance-block` and bounds steering: steer within `actions[]`, route
   `reserved[]` to the human, never direct into `prohibited[]` (an undeclared
   kind is refused as outside the boundary). Consumes the block; does not
   redefine it (`a2a_compliance.governance_block`).
4. **The maker-side cooperative-poll shim** — a maker polls a session-keyed
   file-backed inbox at its checkpoints and honours pending directives
   (`a2a_compliance.inbox`, `a2a_compliance.participant`), driven by the
   compliance send side (`a2a_compliance.channel`).

### Cooperative-poll mechanism — and its honest limit

The maker-side participant is the load-bearing piece (SPEC §9/§11). Delivery is
**cooperative**: a directive is delivered only when the maker reaches
`ControlParticipant.checkpoint()`, and a `halt` is a **cooperative stop at the
next checkpoint — NOT a forced kill**. The maker's own loop must consult
`should_continue()` / `is_held()` and yield. A maker that never checkpoints
cannot be steered by this shim. A forced/instant stop is a harness- or
RVND-level capability the bare protocol does not promise; the shim is written so
it can bind to a real harness send/stop primitive later without changing
callers.

### Quickstart

```bash
pip install -e ".[dev]"
pytest -q          # 30 tests: bare-mode flow, authority, governance bound, null-plane semantics
```

```python
from a2a_compliance import ComplianceAgent, ControlParticipant, FileInbox, GovernanceBlock, Roster

inbox = FileInbox("/tmp/a2a")
block = GovernanceBlock.from_manifest("skills/compliance-fleet/SKILL.md")
comp  = ComplianceAgent("comp-1", "policy-compliance", inbox, Roster(), {"maker-1": block})
maker = ControlParticipant("maker-1", inbox, compliance_actor="comp-1",
                           state_provider=lambda inc: {"trajectory": []})

comp.issue_directive("maker-1", "keep edits in module X", "constrain", target_kind="query_state")
maker.checkpoint()   # maker polls, honours the directive, acks back
```

## Layout

```
a2a-compliance/
├── .claude-plugin/plugin.json          # ctrl-plane plugin ("skills": "./skills/")
├── skills/compliance-fleet/SKILL.md    # skill manifest + governance: block
├── schema/a2a-control-message.schema.json   # the A2A envelope (validated in Phase 1)
├── interfaces/a2a_control.py           # message contract + participant SEAM (Protocols)
├── interfaces/compliance_fleet.py      # value-plane consumption seam (Phase 2, still interface-only)
├── a2a_compliance/                     # Phase-1 working package
│   ├── envelope.py                     #   message construction + wire serialization
│   ├── schema.py                       #   jsonschema validation (guarded)
│   ├── authority.py                    #   role-based authority (team-charter roster)
│   ├── governance_block.py             #   the governance-block reader
│   ├── inbox.py                        #   file-backed cooperative-poll inbox
│   ├── participant.py                  #   maker-side control-participant shim
│   └── channel.py                      #   compliance-agent send side
├── tests/                              # 30 tests; bare-mode end-to-end
├── pyproject.toml                      # package + [dev] test extra
├── SPEC.md                             # the design
├── README.md
├── REUSE.toml, LICENSES/               # licensing placeholders
```

## Neutral spec?

**Yes — recommended.** The universal-and-optional ethos already makes this a
vendor-agnostic protocol; it is the natural neutral complement to
`skill-governance-block` (that declares a maker's boundary; this is the runtime
control within it). At publication the recommendation is a neutral `spec/` core +
a `bindings/` appendix (ctrl = the role-authority binding, loomground = the
value-criterion binding, RVND = the enforcement binding). See SPEC §10.

Local only. No remote; publication is reserved for the owner.

Owner: Felix Krone (flxk1).
