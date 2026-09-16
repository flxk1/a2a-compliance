# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Regression tests for the `wire.verify` submodule/export name collision
shipped in 0.3.0: `from a2a_compliance.wire import verify` returned the
`verify` submodule object (non-callable) instead of the `verify` function
whenever that submodule had already been imported directly, because Python's
import machinery binds a submodule onto its parent package's namespace the
first time it loads -- pre-empting `wire.__getattr__`'s own lazy caching for
any name that shares the submodule's name. Fixed by renaming the submodule
`verify.py` -> `verification.py` so no `wire.__all__` name collides with a
submodule name.

Both tests run in a subprocess to get a genuinely fresh, unpolluted import
state; the fix must hold regardless of what a caller (or pytest's own
collection order) already imported.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(code: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_verify_export_after_submodule_import():
    """Replays the broken sequence: import wire submodules directly (bypassing
    `wire.__getattr__`) BEFORE ever touching the package-level `verify`
    export, then take the export. Locks in that `verify` still resolves to
    the callable regardless of import order."""
    code = (
        "import a2a_compliance.wire.verification\n"
        "import a2a_compliance.wire.schema_registry\n"
        "from a2a_compliance.wire import verify\n"
        "assert callable(verify), f'verify is not callable: {type(verify)!r}'\n"
        "print('ok')\n"
    )
    assert _run(code) == "ok"


# One name is resolved per subprocess run (not the whole of `__all__` in one
# pass): accessing an earlier `__all__` name through `wire.__getattr__` can
# incidentally re-cache a LATER name sourced from the same submodule (see the
# pre-fix `__getattr__`'s now-removed "resolve every lazy name in one pass"
# loop), which would silently self-heal `verify` before the test ever reads
# it and mask the exact defect this guards against. Isolating one name per
# process is what makes this test capable of catching that.
_RESOLVE_ONE_SCRIPT = """
import importlib
import json
import pkgutil

if {preimport}:
    import a2a_compliance.wire as _wire_pkg
    for m in pkgutil.iter_modules(_wire_pkg.__path__):
        importlib.import_module(f"a2a_compliance.wire.{{m.name}}")

import a2a_compliance.wire as wire

value = getattr(wire, {name!r})
print(json.dumps([
    type(value).__module__,
    type(value).__qualname__,
    getattr(value, "__qualname__", None) or getattr(value, "__name__", None),
]))
"""


def test_wire_all_names_order_independent():
    """Class-level guard: for every name in `a2a_compliance.wire.__all__`,
    `from a2a_compliance.wire import <name>` must resolve to the same kind of
    object whether or not the package's own submodules were imported first.
    Catches this collision shape for any current or future lazily-exported
    name (`verify`, `schema_registry`'s names, ...), not just this instance.

    `canonical` is deliberately exported AS its submodule (a module object)
    in both orders -- the invariant is "resolves the same both ways", not
    "no __all__ name may equal a submodule name".
    """
    from a2a_compliance import wire as wire_pkg

    results = {}
    for name in wire_pkg.__all__:
        clean = json.loads(_run(_RESOLVE_ONE_SCRIPT.format(preimport=False, name=name)))
        submodules_first = json.loads(_run(_RESOLVE_ONE_SCRIPT.format(preimport=True, name=name)))
        assert clean == submodules_first, f"{name}: clean={clean} submodules_first={submodules_first}"
        results[name] = clean
    # Sanity: the resolved kind actually looks right, not just "consistently
    # wrong" both times (e.g. a `canonical`-style module masking a real bug).
    assert results["verify"][1] == "function"
