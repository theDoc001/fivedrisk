"""minimal_gate.py — the smallest possible fivedrisk integration.

Run:
    PYTHON_BIN="${PYTHON_BIN:-python3}"
    "$PYTHON_BIN" -m pip install "fivedrisk>=0.7.1,<0.8.0"
    "$PYTHON_BIN" -I -c 'import importlib.machinery as m, importlib.metadata as d, pathlib, sys; x=d.distribution("fivedrisk"); r=next((p for p in x.files or () if str(p).replace("\\","/")=="fivedrisk/__init__.py"), None); r is not None or sys.exit("fivedrisk distribution has no recorded package"); e=pathlib.Path(x.locate_file(r)).resolve(strict=True); s=m.PathFinder.find_spec("fivedrisk",[str(e.parent.parent)]); a=pathlib.Path(s.origin).resolve(strict=True) if s and s.origin else None; a==e or sys.exit("fivedrisk provenance mismatch"); print(f"verified fivedrisk {x.version}: {e}")'
    "$PYTHON_BIN" examples/minimal_gate.py

What you see:
    - One GREEN action that passes the gate (a benign `echo` command).
    - One RED action that is blocked (`rm -rf` destructive command).
    - The 5D rationale for each decision.
    - One audit-log row per gated call.

Nothing in this file requires an LLM, an API key, or network access — and the
executor is a SIMULATOR (no real shell runs), so the demo is safe even if the
gate is misconfigured.

Why Bash for the demo: fivedrisk's shipped `tool_defaults` and
`bash_overrides` cover Bash well, so the rationale strings are concrete.
To gate domain-specific tools (`send_invoice`, `query_warehouse`, etc.),
extend `tool_defaults` in your `policy.yaml`. See `docs/quickstart.md`
section 5 for the recipe.
"""

from fivedrisk.hooks import FivedriskDenial, gate, configure
from fivedrisk.logger import DecisionLog


configure(policy_path=None)  # use shipped defaults; pass a YAML path to customize


@gate(tool_name="Bash", autonomy_context=2)
def run_shell(command: str) -> str:
    """Simulate executing a shell command. Gated by 5D before it 'runs'.

    M15: this demo deliberately does NOT execute a real shell (no subprocess, no
    shell=True), so that even a scoring regression that let a destructive command
    slip past the gate cannot delete anything on your machine. In real code, swap
    this body for your actual executor — but only for commands you have gated.
    """
    return f"[simulated] would execute: {command}"


def main() -> None:
    # Benign command → GREEN → executes
    print("--- benign call ---")
    print(run_shell(command="echo hello-from-fivedrisk"))

    # Destructive command → fivedrisk's bash_overrides catch `rm -rf` → RED block
    print("\n--- hostile call ---")
    try:
        run_shell(command="rm -rf /tmp/some/important/path")
    except FivedriskDenial as exc:
        # @gate raises FivedriskDenial (BandBlockError) on a block — NOT ValueError
        # (catching ValueError would let a block fall through as a fail-open).
        print(f"blocked: {exc}")

    # Inspect the audit log: every gated call leaves a row.
    print("\n--- audit log (last 5) ---")
    log = DecisionLog()
    for row in log.query_recent(limit=5):
        print(f"  {row['band']:6}  {row['tool_name']:8}  {row['rationale']}")


if __name__ == "__main__":
    main()
