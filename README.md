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

## Install

From the `loomground-plugins` marketplace (publication pending):

```
/plugin marketplace add flxk1/loomground-plugins
/plugin install a2a-compliance@loomground
```

Directly from GitHub, with pip:

```
pip install "git+https://github.com/flxk1/a2a-compliance.git"
```

Base install has zero hard dependencies (`jsonschema` and `PyYAML` are optional
extras — `.[schema]`, `.[manifest]`, or `.[dev]` for both plus `pytest`); see
[Two overriding invariants](#two-overriding-invariants) above.

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

## Status — bare + value-grounding are runnable

**The bare A2A channel + role authority AND the loomground value-grounding layer
are built and tested; RVND enforcement is still design.** The `a2a_compliance`
package runs the control channel end to end with **zero loomground and zero
RVND**, and, when any loomground value plane is present, draws its
steer/hold/escalate from the grounded value graph — per-plane, degrading each
dimension independently to the advisory reading when its plane is absent. See
[`SPEC.md`](SPEC.md) for the full design (all three modes, the value-plane seam
with its honest per-plane read, the RVND adapter, phasing, and open gaps).

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

## Value grounding — steer/hold/escalate drawn from the value graph

When a loomground value plane is present, a compliance agent derives its
criterion from the grounded value graph instead of the role's advisory
judgement. The seam lives in `a2a_compliance.planes` (per-plane consumption) and
`a2a_compliance.grounding` (the fleet's derivation + decision), reached from the
send side via `ComplianceAgent.ground_and_steer(maker, context)`.

Each of the six planes is consumed as a **general capability** behind an
availability probe. `planes.available(name)` uses `find_spec` — it does **not**
import the plane, so the bare path stays loomground-free; the real plane import
happens only inside `planes.assess`, when the plane is present and actually
consumed. An absent plane (or one that raises) degrades **that one dimension** to
the advisory reading with honest provenance (`advisory-absent`); every other
dimension is unaffected. With no plane present, `grounding` is `null` — exactly
the bare behaviour.

| plane | package | grounded criterion |
|---|---|---|
| deontic | `deontic` | the maker's proposed action collides with a policy prohibition (O-vs-F clash) |
| norm | `loomground_norm` | prose policy → extracted O/P/F duties; does the action match one? |
| mandate | `loomground_mandate` | does the maker's trajectory serve the purpose it was given? |
| escalation | `loomground_escalation` | requested autonomy vs the ceiling the factors leave |
| proxy | `loomground_proxy` | Goodhart: is a proxy metric gamed (up while its value fell)? |
| falsifiability | `loomground_falsifiability` | does the maker's evidence clear the support floor? |

Each returns the shared solver `Verdict` (SATISFIED / NOT_SATISFIED / OPEN). The
findings fold into the envelope's `grounding` block (weakest-link, OPEN-dominant)
and map to a control action:

| grounded finding | control action |
|---|---|
| prohibition collision (deontic) · gamed proxy | **hold** |
| over the escalation ceiling | **route-human** (reserved) |
| mandate divergence · norm breach | **steer** (`issue-directive`, in-boundary) |
| any remaining applicable **OPEN** | **route-human** (OPEN is never a silent pass) |
| all satisfied | **no-steer** |

A directive may be **partly grounded** — some dimensions grounded, others
advisory — and the envelope carries each dimension's own provenance.

### The compile → ground handoff

[`policy-compiler`](../policy-compiler) compiles a written policy into O/P/F norms
and emits them with `CompiledPolicy.to_grounding_seam()`. The fleet accepts that
payload as its norm base (`accept_compiled_policy`) and grounds a maker's proposed
action against the compiled prohibitions/obligations via the deontic plane — one
chain from policy prose to a grounded hold.

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

### Live send/stop transport

`a2a_compliance/harness.py` is the enforceable counterpart to the cooperative
poll — an **optional, opt-in** transport for makers the fleet **spawns**. It is
not on the default import path (`import a2a_compliance` pulls in no harness or
subprocess-spawn driver); callers opt in with `from a2a_compliance import
harness`. It satisfies the same put/poll transport seam `FileInbox` does, so a
`ComplianceAgent(inbox=harness_transport)` binds real send/stop **without
changing callers**, delivering the identical `query-state` / `issue-directive` /
`hold` / `resume` / `halt` envelopes.

Two honest tiers:

- **Spawn-owned maker** — a maker this transport launched. `deliver()` sends a
  directive over the file-inbox channel the maker drains at its checkpoints;
  `stop()` is a **real termination** of the child process. Genuinely enforceable
  send/stop.
- **Maker it did NOT spawn** — cooperative fallback: `deliver()` / `stop()`
  delegate to the plain `FileInbox`, observed at the maker's next checkpoint. The
  harness does not expose arbitrary live cross-session messaging, so it does not
  claim a forced kill of a maker it does not own — that stays a cooperative stop.

The `Spawner` Protocol is the driver seam. `SubprocessSpawner` is the real,
testable default (a maker runs as a child process). `ClaudeHarnessSpawner` is a
documented injection point for the Claude-Code harness — spawn ~ the Agent tool,
stop ~ TaskStop — which are host agent-tools, not a Python API, so it is a seam
the host wires, not a working in-module driver.

### Quickstart

```bash
pip install -e ".[dev]"
pytest -q          # bare-mode flow, authority, governance bound, null-plane semantics,
                   # and value grounding (grounded / partial / compile->ground)
```

The grounded tests run the fleet in a subprocess, so the parent test process
imports no loomground module and the bare-path invariant stays honest. They
consume whichever planes are installed; the not-installed planes are read from
their on-disk `src` in the subprocess to exercise full six-plane grounding.

```python
from a2a_compliance import ComplianceAgent, FileInbox, Roster, GroundingContext, accept_compiled_policy

comp = ComplianceAgent("comp-1", "policy-compliance", FileInbox("/tmp/a2a"), Roster())
policy = accept_compiled_policy(compiled_policy.to_grounding_seam())  # from policy-compiler
ctx = GroundingContext(
    maker_id="maker-1",
    proposed_action={"bearer": "maker", "action": "delete the audit trail"},
    policy=policy,
)
disp = comp.ground_and_steer("maker-1", ctx)   # deontic collision -> a grounded hold
disp.grounding_result.recommended_action       # "hold"
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
├── interfaces/compliance_fleet.py      # value-plane consumption seam (Protocols)
├── a2a_compliance/                     # working package
│   ├── envelope.py                     #   message construction + wire serialization
│   ├── schema.py                       #   jsonschema validation (guarded)
│   ├── authority.py                    #   role-based authority (team-charter roster)
│   ├── governance_block.py             #   the governance-block reader
│   ├── inbox.py                        #   file-backed cooperative-poll inbox
│   ├── participant.py                  #   maker-side control-participant shim
│   ├── harness.py                      #   opt-in live send/stop transport (spawn-owned) + Spawner seam
│   ├── channel.py                      #   compliance-agent send side (+ ground_and_steer)
│   ├── planes.py                       #   per-plane loomground consumption (availability-guarded)
│   └── grounding.py                    #   the fleet's derivation + steer/hold/escalate mapping
├── tests/                              # bare-mode end-to-end + value grounding
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

Owner: flxk1.
