"""example_gate.py — the smallest end-to-end fivedrisk demo (framework-neutral).

Run with the interpreter selected by the setup workflow:
    <SELECTED_PYTHON> -I <SKILL_ROOT>/scripts/example_gate.py

Shows the end-to-end gate outcome in ~40 lines: a GREEN benign call that executes, a RED
destructive call that is blocked before it runs, the 5D rationale for each, and the
last five audit-log rows. No LLM, no API key, no network. The executor is simulated
(no real shell), so even a scoring regression can't delete anything.

This mirrors `examples/minimal_gate.py` in the fivedrisk repo; it lives in the skill
so the setup playbook can run it as its final verification step.
"""

from __future__ import annotations

import os
import sys

from fivedrisk.hooks import FivedriskDenial, configure, gate
from fivedrisk.logger import DecisionLog

# Absence selects shipped defaults. A non-empty explicit path is always passed to
# the loader so a missing or invalid operator policy fails loudly.
_policy = os.environ.get("FIVEDRISK_POLICY_PATH")
configure(policy_path=_policy or None)


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
    else:
        raise RuntimeError("destructive simulated call was not denied")

    print("\n--- audit log (last 5 decisions) ---")
    for row in DecisionLog().query_recent(limit=5):
        print(f"  {row['band']:6}  {row['tool_name']:8}  {row['rationale']}")

    print(
        f"\nFor a running summary:  {sys.executable} "
        "-I -m fivedrisk._bootstrap stats"
    )


if __name__ == "__main__":
    main()
