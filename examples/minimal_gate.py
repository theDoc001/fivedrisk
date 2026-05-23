"""minimal_gate.py — the smallest possible fivedrisk integration.

Run:
    pip install fivedrisk
    python examples/minimal_gate.py

What you see:
    - One GREEN action that executes (a benign `ls` command).
    - One RED action that is blocked (`rm -rf` destructive command).
    - The 5D rationale for each decision.
    - One audit-log row per gated call.

Nothing in this file requires an LLM, an API key, or network access.

Why Bash for the demo: fivedrisk's shipped `tool_defaults` and
`bash_overrides` cover Bash well, so the rationale strings are concrete.
To gate domain-specific tools (`send_invoice`, `query_warehouse`, etc.),
extend `tool_defaults` in your `policy.yaml`. See `docs/quickstart.md`
section 5 for the recipe.
"""

import subprocess

from fivedrisk.hooks import gate, configure
from fivedrisk.logger import DecisionLog


configure(policy_path=None)  # use shipped defaults; pass a YAML path to customize


@gate(tool_name="Bash", autonomy_context=2)
def run_shell(command: str) -> str:
    """Execute a shell command. Gated by 5D before it runs."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def main() -> None:
    # Benign command → GREEN → executes
    print("--- benign call ---")
    print(run_shell(command="echo hello-from-fivedrisk"))

    # Destructive command → fivedrisk's bash_overrides catch `rm -rf` → RED block
    print("\n--- hostile call ---")
    try:
        run_shell(command="rm -rf /tmp/some/important/path")
    except ValueError as exc:
        print(f"blocked: {exc}")

    # Inspect the audit log: every gated call leaves a row.
    print("\n--- audit log (last 5) ---")
    log = DecisionLog()
    for row in log.query_recent(limit=5):
        print(f"  {row['band']:6}  {row['tool_name']:8}  {row['rationale']}")


if __name__ == "__main__":
    main()
