"""Allow ``python -m agent_firewall`` to invoke the CLI.

This module is intentionally minimal: it delegates everything to
``agent_firewall.cli`` and must never contain authorization logic.
"""

from .cli import entry_point

if __name__ == "__main__":
    entry_point()
