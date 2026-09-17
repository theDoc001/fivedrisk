#!/usr/bin/env python3
"""example_gate.py — the smallest end-to-end fivedrisk demo (framework-neutral).

Run (after `pip install fivedrisk`):
    python3 scripts/example_gate.py

Shows the four-band outcome in ~40 lines: a GREEN benign call that executes, a RED
destructive call that is blocked before it runs, the 5D rationale for each, and the
last five audit-log rows. No LLM, no API key, no network. The executor is simulated
(no real shell), so even a scoring regression can't delete anything.

This mirrors `examples/minimal_gate.py` in the fivedrisk repo; it lives in the skill
so the setup playbook can run it as its final verification step.
"""

from __future__ import annotations

import os
from pathlib import Path

from fivedrisk.hooks import FivedriskDenial, configure, gate
from fivedrisk.logger import DecisionLog

# Load the operator's policy if FIVEDRISK_POLICY_PATH points at one, else the
# shipped defaults. No broad except — a real misconfig should fail loud.
_policy = os.environ.get("FIVEDRISK_POLICY_PATH")
configure(policy_path=_policy if _policy and Path(_policy).expanduser().exists() else None)


@gate(tool_name="Bash", autonomy_context=2)
def run_shell(command: str) -> str:
    """Simulated executor — gated by 5D before it 'runs'. Never touches a real shell."""
    return f"[simulated] would execute: {command}"


def main() -> None:
    print("--- benign call (expect GREEN, executes) ---")
    print(run_shell(command="echo hello-from-fivedrisk"))

    print("\n--- destructive call (expect RED, blocked before it runs) ---")
    try:
        run_shell(command="rm -rf /tmp/some/important/path")
    except FivedriskDenial as exc:
        # @gate raises FivedriskDenial (e.g. BandBlockError) on a block. It does
        # NOT subclass ValueError — catching ValueError would let a block fall
        # through as a fail-open, so catch the denial base explicitly.
        print(f"blocked: {exc}")

    print("\n--- audit log (last 5 decisions) ---")
    for row in DecisionLog().query_recent(limit=5):
        print(f"  {row['band']:6}  {row['tool_name']:8}  {row['rationale']}")

    print("\nFor a running summary:  python3 -m fivedrisk stats")


if __name__ == "__main__":
    main()
