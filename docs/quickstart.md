# fivedrisk quickstart

End-to-end in 5 minutes. By the end you will have a Python function gated by 5D scoring, an audit log row, and a policy file you can tune for your deployment.

## 1. Install

```bash
pip install fivedrisk
python -c "import fivedrisk; print(fivedrisk.__version__)"
```

## 2. Gate a function with @gate

Save as `try_fivedrisk.py`:

```python
from fivedrisk.hooks import gate, configure
from fivedrisk import load_policy

configure(policy_path=None)  # uses sensible defaults

@gate(tool_name="write_to_database", autonomy_context=2)
def write_record(table: str, data: dict) -> str:
    # Real code would write to the database here.
    return f"wrote {len(data)} fields to {table}"

print(write_record("users", {"name": "Loren"}))         # GREEN → executes
try:
    print(write_record("users", {"command": "DROP TABLE users"}))  # RED → blocked
except ValueError as e:
    print("blocked:", e)
```

Run it. You will see one success and one block. The block raises `ValueError` because no `on_block` callback was supplied; pass one to customize behavior.

## 3. Inspect the audit log

```python
from fivedrisk.logger import DecisionLog

log = DecisionLog()
for row in log.query_recent(limit=5):
    print(row["band"], row["tool_name"], row["rationale"])
```

Every gated call writes a row. SQLite by default at `~/.fivedrisk/decisions.db`; override via `configure(log_path=...)`.

## 4. Pick a preset (or tune your own)

Five YAML presets ship at `fivedrisk/policies/presets/`:

- `read_only.yaml`. Agents that only read. Anything that writes or executes escalates.
- `human_approval_required.yaml`. Every write requires HITL approval.
- `financial_operations.yaml`. Money-moving workflows. Strict thresholds plus identity required.
- `customer_data.yaml`. PII-handling agents. Data sensitivity weighted heaviest.
- `code_execution.yaml`. Agents that run arbitrary code. Bash overrides tightened.

```python
from fivedrisk import load_policy
policy = load_policy("path/to/fivedrisk/policies/presets/read_only.yaml")
```

Or copy one to `policy.yaml` in your project and edit. The schema is documented inline at the top of every preset.

## 5. Narrow your agent's scope so 5D actually catches what matters

5D is a policy gate, not a magic detector. It works best when the agent's tool surface, autonomy context, and use cases are narrow and explicit. Before you ship:

**Narrow the tool surface.** Agents should expose only the tools they need. If the agent will never call `Bash`, do not register `Bash`. The smaller the surface, the fewer policy gaps.

**Pick the right autonomy context.** `0` for human-in-the-loop interactive workflows, `2` for agent-supervised pipelines, `4` for fully unattended. fivedrisk weights autonomy into every score: the same action is more dangerous when nobody is watching.

**Extend `tool_defaults` and `bash_overrides` for your exact deployment.** The shipped defaults cover common tools (Read, Write, Edit, Bash, WebFetch). For domain-specific tools, add entries:

```yaml
# policy.yaml
tool_defaults:
  send_invoice:
    tool_privilege: 3        # talks to billing system
    reversibility: 3         # invoices are hard to unsend
    external_impact: 3       # external customer
  query_warehouse:
    tool_privilege: 1        # read-only
    reversibility: 0
    external_impact: 0

bash_overrides:
  "kubectl apply":
    tool_privilege: 4
    reversibility: 3
  "terraform destroy":
    tool_privilege: 4
    reversibility: 4
```

The classifier reads these baselines. Without your domain knowledge, scoring falls back to conservative defaults that may over- or under-fire.

**Write down the use cases.** Before tuning thresholds, list the action sequences your agent should perform and the sequences it should refuse. Score each by hand. The resulting `policy.yaml` thresholds should make the allow-list GREEN and the deny-list RED with comfortable margins. If you cannot articulate the use cases, fivedrisk cannot enforce them.

## 6. Add an injection scan and a destination policy

```python
from fivedrisk.hooks import scan_input_for_injection, configure

configure(
    enforce_destination_policy=True,
    destination_allowlist=["api.yourcompany.com", "internal.db"],
)

if scan_input_for_injection(user_message):
    # Block, log, escalate; do not pass the prompt to the model.
    ...
```

## What is next

- Worked examples (minimal `@gate`, OpenAI Agents SDK hook, LangGraph multi-step): [`examples/`](../examples/).
- Architecture: [`fivedrisk/ARCHITECTURE.md`](../fivedrisk/ARCHITECTURE.md).
- Markov SafetyDrift for compositional attacks: README "SafetyDrift" section.
- Audit log fields and SIEM export: README "Audit log" section.
- Coverage docs for OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS: top-level `dev/`.

## Honest limits

fivedrisk is a runtime governance substrate. It does not replace prompt-level guardrails, semantic content scanners (LLM Guard, Lakera, Pangea), or human review. Best results: pair fivedrisk as the fast deterministic pre-filter with one LLM-based scanner on YELLOW and ORANGE escalations, plus HITL on ORANGE-and-above.
