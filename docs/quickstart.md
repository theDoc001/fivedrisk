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

Every gated call writes a row. SQLite by default at `fivedrisk_decisions.db`; override via `configure(log_path=...)` or pass a path to `DecisionLog(path)`.

### Score + DecisionLog in one call

If you are scoring actions outside the `@gate` decorator (e.g. custom events, batch ingest), pair `score()` directly with `DecisionLog.log()` to persist each decision:

```python
from fivedrisk import Action, score, load_policy
from fivedrisk.logger import DecisionLog

policy = load_policy("policy.yaml")
log = DecisionLog("audit.db")    # SQLite file path

action = Action(
    tool_name="Bash",
    data_sensitivity=1,
    tool_privilege=3,
    reversibility=4,
    external_impact=2,
    autonomy_context=2,
)
result = score(action, policy)
log.log(result)                   # one call, decision persisted

# Later: query the log
for row in log.query_recent(limit=10):
    print(f"{row['band']:6}  {row['tool_name']:10}  {row['rationale']}")
```

## 3b. Score a custom (non-tool-call) action

`classify_tool_call` is the convenient entry point for agent tool calls. For events that are not agent tool calls (vault writes, ingest events, document processing, scheduled jobs), construct an `Action` directly:

```python
from fivedrisk import Action, score, load_policy, Band

# Higher values = more risk on every axis. Scale is 0-4.
action = Action(
    tool_name="vault_write",          # any free-form label
    data_sensitivity=2,               # 0 = public, 4 = credentials / secrets
    tool_privilege=2,                 # 0 = read-only, 4 = destructive
    reversibility=3,                  # 0 = trivially undoable, 4 = irreversible
    external_impact=0,                # 0 = local-only, 4 = untrusted external
    autonomy_context=1,               # 0 = user-direct, 4 = fully autonomous
    metadata={"event": "vault_write", "source": "speci"},
)

result = score(action, load_policy("policy.yaml"))
print(result.band)        # Band.GREEN, YELLOW, ORANGE, or RED
print(result.rationale)   # human-readable reason
```

The deterministic scoring engine works for any `Action` shape; tool-call classification is just one entry point.

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
