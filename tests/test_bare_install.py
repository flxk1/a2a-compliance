"""Proves the bare-install guarantee: `import a2a_compliance` and
`import a2a_compliance.team` work with jsonschema, referencing AND
cryptography all absent -- run in a real subprocess with those three
blocked at the import-system level (not merely "not yet imported"), since
an in-process test can't un-import an already-loaded package."""

import subprocess
import sys
from pathlib import Path

PROBE = Path(__file__).parent / "_bare_install_probe.py"


def test_bare_install_survives_without_jsonschema_referencing_or_cryptography():
    result = subprocess.run(
        [sys.executable, str(PROBE)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BARE_INSTALL_OK" in result.stdout
