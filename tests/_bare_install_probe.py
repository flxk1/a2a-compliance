"""Run as a subprocess (see test_bare_install.py), never imported directly:
installs a meta-path import blocker for jsonschema/referencing/cryptography
BEFORE touching a2a_compliance, then proves the package imports and its
canonical-digest path works with none of the three present. Exits 0 on
success; any exception/non-zero exit means the bare-install guarantee is
broken."""

import sys

BLOCKED = {"jsonschema", "referencing", "cryptography"}


class _Blocker:
    def find_spec(self, fullname, path, target=None):
        if fullname.split(".", 1)[0] in BLOCKED:
            raise ImportError(f"bare-install probe: {fullname!r} is blocked")
        return None


sys.meta_path.insert(0, _Blocker())

import a2a_compliance  # noqa: E402,F401
import a2a_compliance.team  # noqa: E402,F401
from a2a_compliance.wire import canonical  # noqa: E402

assert canonical.digest_hex({"a": 1}) == canonical.digest_hex({"a": 1})

for blocked in BLOCKED:
    assert blocked not in sys.modules, f"{blocked} got imported despite being blocked"

print("BARE_INSTALL_OK")
