"""EXAMPLE conformance adapter for E3 (plan: 'Host adapters' -- "a generic
subprocess adapter for conformance tests"). NOT core: not listed in
`[tool.setuptools] packages` in pyproject.toml, so it is never part of the
installed wheel; `a2a_compliance` never imports this module. This is the
ONLY place in this repository that calls `subprocess` -- the fixed trust
boundary (plan) holds core `a2a_compliance.wire` to zero dispatch/effect
code, and this file is where that boundary's "host side" is demonstrated.

The governed tool is `echo`: a fixed, harmless executable (`/bin/echo`),
invoked with the caller-supplied message as ONE argv element, `shell=False`.
Passing an argv list rather than a shell string means `message` can never
break out into a second command -- there is no shell to inject into. No
network, no file writes, no destructive verb. Never grow this adapter to
run anything else.

`GovernedEchoExecutor.execute` is the single call site that can produce a
real effect in this whole module; nothing else here holds a path to it. It
is reachable ONLY via `SubprocessAdapter.consume_and_execute`, which is
core's `wire.executor.consume_and_execute` (verify -> match ->
atomic-consume -> execute -> receipt) with this executor injected --
there is no direct/debug/shortcut method on this class that calls
`execute` without going through that gate. That is what lets this adapter
honestly claim the `mediated` enforcement grade (plan: 'Outcome' -- "a
bypassable adapter cannot claim mediated"); `enforcement_grade()` below
does not merely assert it, it re-checks it live every time it's asked.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from a2a_compliance.wire.admission import Issuer
from a2a_compliance.wire.executor import (
    ExecutionOutcome,
    ExecutionResult,
    consume_and_execute,
)
from a2a_compliance.wire.trust import RevocationStore, TrustStore
from a2a_compliance.wire.verification import NonceStore

GOVERNED_TOOL = "echo"
_ECHO = shutil.which("echo") or "/bin/echo"


class GovernedEchoExecutor:
    """Implements `wire.executor.ExecutorPort`. The ONLY code in this
    module that touches `subprocess`. `calls` is a test-visible record of
    every effect this executor actually produced -- not part of the port
    contract, present so a conformance test can assert a rejected/bypassed
    attempt left it at zero."""

    def __init__(
        self, *, executor_id: str = "adapter:subprocess-echo", executor_role: str = "tool-executor",
    ) -> None:
        self.executor_id = executor_id
        self.executor_role = executor_role
        self.calls: list[tuple[str, dict]] = []

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome:
        if tool != GOVERNED_TOOL:
            raise ValueError(f"this adapter only governs {GOVERNED_TOOL!r}, not {tool!r}")
        message = arguments.get("message", "")
        if not isinstance(message, str):
            raise ValueError("arguments['message'] must be a string")
        self.calls.append((tool, dict(arguments)))
        completed = subprocess.run(
            [_ECHO, message], capture_output=True, text=True, timeout=5, shell=False, check=False,
        )
        return ExecutionOutcome(
            effect={"stdout": completed.stdout, "returncode": completed.returncode},
            executor_id=self.executor_id, executor_role=self.executor_role,
        )


@dataclass
class SubprocessAdapter:
    """The generic subprocess conformance adapter. Implements the one
    host-adapter call this slice covers: `consume_and_execute(ExecutionPermit)
    -> ToolReceipt[]` (plan: 'Host adapters', call 3 of 4 -- `prepare`,
    `request_approval` and `observe` are later slices, not this one)."""

    trust_store: TrustStore
    nonce_store: NonceStore
    signer: Issuer
    revocation_store: Optional[RevocationStore] = None
    executor: GovernedEchoExecutor = field(default_factory=GovernedEchoExecutor)

    def consume_and_execute(
        self, permit: Optional[dict], *, tool: str, arguments: dict,
        dispatch_id: str, now: Optional[datetime] = None,
    ) -> tuple[list[dict], ExecutionResult]:
        """Host-adapter-shaped wrapper over core's `wire.executor.
        consume_and_execute`: one permit maps to one tool call maps to
        zero-or-one `ToolReceipt`, returned as a list per the plan's
        `ToolReceipt[]` adapter signature. `permit=None`/malformed is a
        valid bypass ATTEMPT, not a caller error -- rejected below, same as
        any other invalid permit; not raised."""
        result = consume_and_execute(
            permit if isinstance(permit, dict) else {},
            tool=tool, arguments=arguments,
            trust_store=self.trust_store, nonce_store=self.nonce_store,
            executor=self.executor, signer=self.signer, dispatch_id=dispatch_id,
            revocation_store=self.revocation_store, now=now,
        )
        receipts = [result.receipt] if result.ok else []
        return receipts, result

    def _bypass_is_rejected(self) -> bool:
        """Live self-check, not a standing assumption: attempt the exact
        bypass this deployment must reject (no permit at all) and confirm
        it produced neither an `ok` result nor a real executor call. Safe
        to call repeatedly -- an empty permit fails `wire.verification.verify`
        before anything is consumed or executed, so this never dispatches."""
        calls_before = len(self.executor.calls)
        _, result = self.consume_and_execute(
            None, tool=GOVERNED_TOOL, arguments={"message": "__bypass_probe__"},
            dispatch_id="bypass-probe",
        )
        return (not result.ok) and len(self.executor.calls) == calls_before

    def enforcement_grade(self) -> str:
        """This deployment's ACTUAL, re-verified grade (plan: 'Outcome').
        `mediated` only if a bypass attempt is genuinely rejected right
        now; otherwise `advisory` -- never a claim taken on faith."""
        return "mediated" if self._bypass_is_rejected() else "advisory"
