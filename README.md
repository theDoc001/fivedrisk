# fivedrisk — the policy gate for AI agents

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml/badge.svg)](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/fivedrisk.svg)](https://pypi.org/project/fivedrisk/)

**Score every action. Audit every decision. Keep the decisions you choose to.**

fivedrisk is the fast deterministic policy gate that runs before your LLM-based safety stack. Every AI agent action is scored on five risk dimensions, banded GREEN / YELLOW / ORANGE / RED, and resolved in 0.2 to 2.9 ms on a single CPU thread. No LLM in the decision path. No external service.

Built in Vienna, Austria. Architecturally sovereign: no hyperscaler dependency, runs entirely on your own infrastructure. Apache 2.0.

---

## Deterministic first, optional semantic second

The stages answer different questions. fivedrisk asks whether an action is permitted: rules evaluated over the action envelope, its policy, the caller's identity and the sequence so far, with the record naming the policy that decided. A semantic scanner asks whether a span of text is malicious or sensitive, which is a judgment. fivedrisk does not bundle or invoke a semantic scanner. A deployment may add one for explicitly named ambiguity classes, but it may only preserve or raise the deterministic severity, never lower it. YELLOW is opt-in and its score range folds into GREEN by default; ORANGE remains approval-required.

The order is the design. The deterministic stage runs first and reaches a verdict with no model call, so every action it resolves costs no inference, no round trip and no tokens, and no prompt leaves your estate. An optional semantic stage runs only for ambiguity classes the deployment explicitly routes.

They run in series because the questions differ, not because one is a cheaper version of the other. A deterministic gate fails by holding a wrong rule, which you can read, test and fix. A semantic scanner fails by making a wrong call on an input nobody anticipated. Neither failure mode substitutes for the other.

How much of your action volume reaches an optional second stage depends on your traffic and policy. Measure that fraction, latency, and compute on your deployment rather than taking a number from a README.

```
agent action
    │
    ▼
[fivedrisk]  ← 0.2 to 2.9 ms, deterministic, audited
    │
    ├── GREEN  ─────────────► execute
    ├── YELLOW ───────────► execute / enhanced log  (opt-in band)
    ├── ORANGE ─► HITL ────────► approve / deny
    └── RED    ─────────────► block, audit, alert
```

The arrows show the shipped default dispositions, not the definition of each band.
A band is severity; a deployment may remap its disposition. Optional observer routing
is deployment-owned and is not shown as a shipped path. Concrete adapters below state
where their integration contract deliberately blocks or requests approval.

**What it is.** A runtime action-governance layer for AI agents. Per-action 5D scoring, HITL escalation, append-only audit log, 16-state Markov SafetyDrift for compositional attacks, identity capture, and an NDJSON event stream for SIEM. Think OPA for AI agents.

**What it is not.** A general LLM guardrail suite, a semantic content scanner, or a replacement for one. It is the deterministic pre-filter that lets a semantic scanner and your own governance practices (tool and scope narrowing, prompt guardrails, system prompts) scale.

fivedrisk assesses whether an action is **safe to run** (dangerous, out-of-policy, or out-of-pattern), not whether the agent's decision is **correct or high quality**. It is a security gate, not a quality judge. Full scope: [`docs/spec/scope.md`](docs/spec/scope.md).

---

## Quickstart in 5 minutes

```bash
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -I -m pip install "fivedrisk>=0.7.1,<0.8.0"
"$PYTHON_BIN" -I -c 'import importlib.machinery as m, importlib.metadata as d, pathlib, sys; x=d.distribution("fivedrisk"); r=next((p for p in x.files or () if str(p).replace("\\","/")=="fivedrisk/__init__.py"), None); r is not None or sys.exit("fivedrisk distribution has no recorded package"); e=pathlib.Path(x.locate_file(r)).resolve(strict=True); s=m.PathFinder.find_spec("fivedrisk",[str(e.parent.parent)]); a=pathlib.Path(s.origin).resolve(strict=True) if s and s.origin else None; a==e or sys.exit("fivedrisk provenance mismatch"); print(f"verified fivedrisk {x.version}: {e}")'
```

Wrap any function. The gate scores the call, and the action only runs if the band clears.

```python
from fivedrisk.hooks import gate

@gate(tool_name="write_to_database", autonomy_context=2)
async def write_record(table: str, data: dict) -> None:
    ...  # only executes if 5D scores GREEN or YELLOW
         # Shipped @gate default: ORANGE → approval; RED → block
```

`@gate` snapshots and executes the same detached action data it scores. Action
arguments must use exact built-in `None`, `bool`, `int`, finite `float`, `str`,
`list`, `tuple`, or string-keyed `dict` values; subclasses and custom objects
raise `GateInputError` (or route through `on_block`) before the function runs.
Convert paths, dataclasses, handles, and other objects explicitly at the call boundary.
Instance and class methods are unsupported because their receivers are custom objects;
gate a static or free data-only boundary function instead. A `Bash` gate accepts one
exact built-in string in its `command` parameter, never an argv list or tuple.

Full walkthrough including scope-narrowing guidance and per-deployment tuning: [`docs/quickstart.md`](docs/quickstart.md). Copy-paste-runnable integrations: [`examples/`](examples/). Policy presets for common deployment archetypes: [`fivedrisk/policies/presets/`](fivedrisk/policies/presets/).

![fivedrisk demo — injection blocked, rm -rf stopped, SafetyDrift escalation](https://github.com/user-attachments/assets/5d6b9631-c36b-4674-bd3f-3897555f26f8)

---

## Where 5D runs

fivedrisk is an ingredient you drop into your agent stack, not a platform you migrate to. Drop it in via a decorator, a native framework adapter, a structured host hook, or the language-agnostic gateway. Everything below ships today. Not sure which one? Run the setup skill's `detect_framework.py` and it prints the adapter + one-line wiring for what you already have installed.

**Agent frameworks** — provisional adapters built against the frameworks' documented
APIs and tested with local fakes. Pin the framework version and prove a harmless RED
call cannot execute before relying on one. Every adapter is a thin shim over the shared
`fivedrisk.to_verdict` path; RED and ORANGE stop, and invalid input or engine errors fail
closed. Copy-paste wiring: [`references/adapters.md`](fivedrisk-plugin/skills/fivedrisk-setup/references/adapters.md).

| Framework | How you wire it | Entry point |
|---|---|---|
| **CrewAI** | `PRE_TOOL_CALL` hook (blocks via `HookAborted`) | `make_crewai_pre_tool_hook` |
| **OpenAI Agents SDK** | Tool-input guardrail (`reject_content`) | `make_openai_tool_input_guardrail` |
| **Google ADK** | `before_tool_callback` (block-dict) | `make_adk_before_tool_callback` |
| **Pydantic AI** | MCP `process_tool_call` (substitute result) | `make_pydantic_process_tool_call` |
| **Microsoft Agent Framework** | Function-invocation middleware (short-circuit) | `make_ms_agent_framework_middleware` |
| **LangGraph** | Gate node in front of tool-executing nodes | `fivedrisk_gate_node`, `route_by_band` |
| **Anthropic Claude Agent SDK** | PreToolUse / PostToolUse hooks | `fivedrisk_pre_tool`, `fivedrisk_post_tool` |
| **Vercel AI SDK / Genkit** (Node/TS) | `npm i fivedrisk-gateway`; guard your tools | `guardVercelTool`, `guardGenkitTool` |
| **Any Python function** | `@gate` decorator, sync or async | `fivedrisk.hooks.gate` |

**Implementation surfaces** — where you run it, independent of framework.

| Surface | How you wire it | Entry point |
|---|---|---|
| **Claude Code** | PreToolUse gate (ORANGE → native `ask`) + PostToolUse verify | `"$PYTHON_BIN" -I -m fivedrisk._bootstrap claude-hook` |
| **Any non-Python host** (Node, Go, Rust, TypeScript) | Long-lived JSON-lines subprocess | `"$PYTHON_BIN" -I -m fivedrisk._bootstrap gateway stdio` |
| **OpenClaw** | TypeScript plugin over the gateway | [`5d-claw-security`](https://github.com/theDoc001/5d-claw-security) |
| **Setup / field engineering** | Detect your framework; select, copy, and validate an operator-owned policy; verify install | [`fivedrisk-setup` skill](fivedrisk-plugin/skills/fivedrisk-setup/) |

Install the advisory setup skill directly from this public repository with the
[Skills CLI](https://www.skills.sh/docs/cli):

```bash
git clone --branch v0.7.2 --depth 1 https://github.com/theDoc001/fivedrisk.git
cd fivedrisk
npx --yes skills@1.7.2 add . --skill fivedrisk-setup
```

The skill helps design and verify a deployment. It does not install the Python
runtime or intercept an agent's tool calls by itself.

**The gateway** lets any language call the engine over JSON-lines:

```bash
"$PYTHON_BIN" -I -m fivedrisk._bootstrap --policy policy.yaml --log-path /absolute/path/fivedrisk.db gateway stdio
"$PYTHON_BIN" -I -m fivedrisk._bootstrap --policy policy.yaml --log-path /absolute/path/fivedrisk.db gateway score
```

The gateway classifies, scans input, scores, optionally applies session drift, and logs.
It fails closed when a policy enables identity, retry, or token-budget admission because
protocol 1 cannot enforce those controls. Destination allow/deny configured through
Python `configure()` is also outside this surface. See the complete
[`protocol 1 contract`](docs/gateway-protocol.md).

| Surface | Input scans | Session drift | Identity / retry / token admission | Destination control | Audit selection |
|---|---|---|---|---|---|
| `@gate` | yes | yes | enforced | enforced after `configure()` | `configure(log_path=...)` |
| Framework factories | yes | with a static ID or resolver | unsupported policies block | not provided | `log=DecisionLog(...)` |
| LangGraph node | yes | from state | unsupported policies block | enforced after `configure()` | `log=` |
| JSON-lines gateway | yes | from request | unsupported policies block | not provided | required `--log-path` in deployment wiring |
| SDK `fivedrisk_pre_tool` | yes | from payload | unsupported policies block | enforced after `configure()` | `configure(log_path=...)` |
| Claude structured hook | yes | from payload | unsupported policies block | not provided | required CLI/configured path |

---

## What it scores

fivedrisk scores every AI agent action on **5 risk dimensions**, each 0 to 4. Higher value means more risk on every axis. There is no inverted axis: if you find yourself assigning a HIGH score to something SAFE, you are mapping it backward.

| Dimension | What it measures | 0 (low risk) | 4 (high risk) |
|---|---|---|---|
| **D** — Data Sensitivity | Sensitivity of data touched | public | credentials / secrets |
| **T** — Tool Privilege | Power of the tool invoked | read-only | destructive |
| **R** — Reversibility | How easy to undo | trivially undoable | irreversible |
| **E** — External Impact | Blast radius of the action | local-only | untrusted external endpoint |
| **A** — Autonomy Context | Distance from a human-in-the-loop | user-direct | fully autonomous, no human in loop |

Scoring stays deterministic. Bands signal what fivedrisk wants your stack to do; your stack chooses the LLM and the workflow.

### Bands and dispositions

A **band** is the audit-stable severity verdict. A **disposition** is what your deployment does with it. Separating the two is deliberate: a band is a label you can query for years, a disposition is a routing choice you can tune.

| Band | Default disposition | Meaning |
|---|---|---|
| **GREEN** | execute, normal logging | Most actions land here. |
| **YELLOW** | log with full rationale, no HITL | Opt-in moderate-risk tier (see below). |
| **ORANGE** | human-in-the-loop approval | fivedrisk signals; your stack owns the reviewer or workflow. |
| **RED** | blocked | Hard gate or dual control. |

**Default 3-band experience.** GREEN / ORANGE / RED, with YELLOW folded into GREEN. fivedrisk does not auto-promote the model class for ORANGE; it signals, and your stack decides.

**Opt-in 4-band compliance mode.** Set `enable_yellow_band: true` in `policy.yaml` to surface YELLOW as a stable moderate-risk tier between GREEN and ORANGE. YELLOW is the cost-management band: a stable label for audit queries, enhanced logging, no human approval needed. Useful when dashboards or quarterly reports need to track moderate-risk decisions as a population without score-range queries that break when thresholds tune. Within YELLOW, model-class promotion for sensitive data (D2/D3) is a separate opt-in via `yellow_model_escalation: true`; your stack still decides whether to honour it.

Full vocabulary and the disposition ladder (`EXECUTE` / `LOG_ELEVATED` / `ROUTE_OBSERVER` / `ROUTE_HITL` / `BLOCK`): [`docs/spec/taxonomy.md`](docs/spec/taxonomy.md).

---

## Features

- **5D scoring engine** — deterministic, ~40µs per action (p50) on M1, no LLM calls. See [Performance](#performance) for full numbers.
- **Markov SafetyDrift** — 16-state Markov chain detects cumulative risk across action sequences; catches compositional attacks that individual scoring misses.
- **Session accumulator** — O(1) counter-based drift tracking for the common case.
- **Injection scanner** — 24+ regex patterns covering GPT-5/Opus-era evasion (Base64, zero-width Unicode, role hijacks, encoded exec calls).
- **Output leakage scanner** — PII, credentials, crypto keys, injection-echo detection.
- **`@gate` decorator** — wrap any sync or async function with full 5D gating.
- **Native host hooks** — Claude Agent SDK, Claude Code, LangGraph, OpenAI Agents SDK, and a language-agnostic gateway. See [Where 5D runs](#where-5d-runs).
- **Destination policy** — allowlist / denylist for outbound endpoints.
- **Audit log** — append-only SQLite decision log plus optional NDJSON event stream for SIEM delivery; every action recorded.
- **Tamper-evident audit chain** — `verify_chain()` over a per-row hash chain reports the first row that does not recompute, plus six audit columns recording the acting principal, the policy content hash and the full outcome sequence. Evidence, not proof. See [`docs/audit-trail.md`](docs/audit-trail.md).
- **Security policy** — supported versions, how to report a vulnerability, and the advisory for 0.6.0 and earlier: [`SECURITY.md`](SECURITY.md).
- **Policy floor enforcement** — floor rules in `policy.yaml` cannot be overridden at runtime.
- **Defence-in-depth test suite** — see [Benchmark and test suite](#benchmark-and-test-suite) for the full attack-class coverage.
- **Regression suite.** Acceptance, adversarial, integration, packaging, and
  documentation contracts are exercised in CI without a hand-maintained count.

---

## Install

```bash
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -I -m pip install "fivedrisk>=0.7.1,<0.8.0"
"$PYTHON_BIN" -I -c 'import importlib.machinery as m, importlib.metadata as d, pathlib, sys; x=d.distribution("fivedrisk"); r=next((p for p in x.files or () if str(p).replace("\\","/")=="fivedrisk/__init__.py"), None); r is not None or sys.exit("fivedrisk distribution has no recorded package"); e=pathlib.Path(x.locate_file(r)).resolve(strict=True); s=m.PathFinder.find_spec("fivedrisk",[str(e.parent.parent)]); a=pathlib.Path(s.origin).resolve(strict=True) if s and s.origin else None; a==e or sys.exit("fivedrisk provenance mismatch"); print(f"verified fivedrisk {x.version}: {e}")'

# With LangGraph integration
"$PYTHON_BIN" -I -m pip install "fivedrisk[langgraph]>=0.7.1,<0.8.0"
"$PYTHON_BIN" -I -c 'import importlib.machinery as m, importlib.metadata as d, pathlib, sys; x=d.distribution("fivedrisk"); r=next((p for p in x.files or () if str(p).replace("\\","/")=="fivedrisk/__init__.py"), None); r is not None or sys.exit("fivedrisk distribution has no recorded package"); e=pathlib.Path(x.locate_file(r)).resolve(strict=True); s=m.PathFinder.find_spec("fivedrisk",[str(e.parent.parent)]); a=pathlib.Path(s.origin).resolve(strict=True) if s and s.origin else None; a==e or sys.exit("fivedrisk provenance mismatch"); print(f"verified fivedrisk {x.version}: {e}")'
```

Or from an exact VCS ref, only after the user approves both the repository URL and
that ref. Prefer an immutable full commit; never silently substitute VCS after an
index failure. Replace `<FULL_COMMIT>` with the approved commit:

```bash
"$PYTHON_BIN" -I -m pip install "git+https://github.com/theDoc001/fivedrisk.git@<FULL_COMMIT>"
"$PYTHON_BIN" -I -m pip install "git+https://github.com/theDoc001/fivedrisk.git@<FULL_COMMIT>#egg=fivedrisk[langgraph]"
```

---

## Quick start (30 seconds)

```python
from fivedrisk import classify_tool_call, score, load_policy, Band

policy = load_policy("policy.yaml")  # or use defaults
action = classify_tool_call("Bash", {"command": "rm -rf /tmp/cache"}, policy)
result = score(action, policy)

print(result.band)                      # Band.RED
print(result.rationale)                 # "RED — Bash: Tool Privilege=4 ...; Reversibility=4 ..."
print(result.routing.approval_required) # True (routing metadata); RED is still denied by the gate.
```

**With the `@gate` decorator:**

```python
from fivedrisk.hooks import gate, configure

configure(policy_path="policy.yaml")

@gate(tool_name="send_email", autonomy_context=1)
def send_email(to: str, body: str) -> None:
    # only executes if 5D scores GREEN or YELLOW
    smtp.send(to, body)
```

**With the Anthropic Claude Agent SDK:**

```python
from fivedrisk.hooks import fivedrisk_pre_tool, fivedrisk_post_tool

# Register as PreToolUse and PostToolUse hooks in your agent
```

**With LangGraph:**

```python
from fivedrisk.langgraph_node import fivedrisk_gate_node
# Add fivedrisk_gate_node to your StateGraph before any tool-executing node
```

---

## Scoring custom (non-tool-call) actions

`classify_tool_call` is convenient for agent tool calls (Bash, Read, Write, WebFetch, ...) where fivedrisk's classifier already has baselines. For events that are not agent tool calls (vault writes, ingest events, document processing, anything that can be characterized on 5 dimensions), construct an `Action` directly:

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
    metadata={"event": "vault_write", "source": "ingest"},
)

result = score(action, load_policy("policy.yaml"))
print(result.band)        # Band.GREEN, YELLOW, ORANGE, or RED
print(result.rationale)   # human-readable reason
```

The deterministic scoring engine works for any `Action` shape; tool-call classification is just one entry point. Document processing, RAG ingest, scheduled jobs, and any other action surface can be scored on the same five dimensions.

---

## SafetyDrift — why sequence risk matters

A single READ of a config file scores GREEN. But 10 GREENs followed by a write to an external API using credentials extracted two steps earlier is a RED sequence. Most tools miss this.

fivedrisk tracks cumulative session state via a **16-state Markov chain** over `(data_exposure_tier × activity_risk_tier)`. When absorption probability into a dangerous state crosses 0.3, the next action is escalated to ORANGE. At 0.7, it is escalated to RED.

```python
from fivedrisk.markov import MarkovDriftTracker, make_default_transition_matrix

tracker = MarkovDriftTracker(make_default_transition_matrix(), session_id="abc")
bump = tracker.record(scored_action)
if bump:
    print(f"Drift: {bump.reason}, escalated to {bump.escalated_band}")
```

---

## Identity

fivedrisk captures two distinct kinds of identity. They are easy to confuse, so keep them straight:

- **Agent identity** is the AI agent's own workload identity. Which agent is acting.
- **Acting identity** is the principal the action is taken on behalf of. Who authorized it.

Both flow through to the audit log and NDJSON events unchanged.

### Agent identity — the agent's own workload identity

fivedrisk accepts opaque agent identity claims through `Action.metadata["agent_identity"]`. The string flows through unchanged into the audit log, where SOC and SIEM tools can correlate decisions by issuer, subject, or workload URI. SVID, JWT, and X.509 subject DN strings are all supported as opaque data today.

```python
from fivedrisk import classify_tool_call, score

action = classify_tool_call("Bash", {"command": "rm -rf /tmp/cache"})
action.metadata["agent_identity"] = "spiffe://example.org/agents/triage-bot"
result = score(action)
# audit log entry now carries the identity string verbatim
```

Cryptographic validation, structured parsing (JWT claim extraction, X.509 chain verification), and identity-aware policy hooks are not implemented yet.

**Reserved metadata keys.** Some keys in `Action.metadata` have reserved semantics; do not overwrite them with arbitrary values. Today the list is `agent_identity` (the opaque identity claim string above). It will grow over time. Any other key you set on `Action.metadata` is passed through unchanged.

### Acting identity — who authorized the action

`Action.acting_identity` is a typed pass-through primitive for the principal an action is taken on behalf of. Distinct from `agent_identity`, which is the agent's own workload identity, `acting_identity` is who authorized the action.

```python
from fivedrisk import gate, ActingIdentity, PrincipalType, AttestationSource

# Decorator default applies unless the caller overrides per-call
@gate(tool_name="approve_invoice", acting_identity=ActingIdentity(
    principal_id="svc-payroll",
    principal_type=PrincipalType.SERVICE,
    attestation_source=AttestationSource.JWT_CLAIM,
    roles=["finance.approve"],
))
def approve_invoice(invoice_id: str, session_id: str) -> None:
    ...

# Per-call override via the _fivedrisk_acting_identity kwarg
approve_invoice(
    "inv-123",
    session_id="s1",
    _fivedrisk_acting_identity=ActingIdentity(
        principal_id="user-42",
        principal_type=PrincipalType.USER,
        attestation_source=AttestationSource.HTTP_HEADER,
    ),
)
```

**Admission check.** Declare `identity_required: true` in `policy.yaml` to deny actions where the caller supplied no identity (or ANONYMOUS). The deny surfaces as `IdentityRequiredError` and emits an `identity_required_denial` NDJSON event.

```yaml
# @gate-only fragment; other adapters need upstream identity admission
identity_required: true
```

**What ships.** Opaque pass-through capture of `principal_id`, `principal_type` (USER / SERVICE / ROLE / AGENT / ANONYMOUS), `attestation_source` (HTTP_HEADER / JWT_CLAIM / ENV_VAR / AGENT_DECLARED / NONE), and optional `roles` and `data_scope`. Identity-aware policy evaluation beyond the `identity_required` admission check, cryptographic validation, and SPIFFE/SPIRE native binding are on the roadmap.

---

## Audit log

fivedrisk produces an append-only decision log entry for every agent action. Each entry records:

- Risk band and rationale
- Dimension scores (all 5 axes)
- Model routing decision and approval history
- Session drift state
- Injection and leakage scan results
- Optional agent and acting identity (see [Identity](#identity))

Since 0.7.0 the log also answers **who authorised this**, **which policy content decided it**,
and **has any row changed since it was written**, through six additive columns
(`acting_principal_id`, `acting_principal_type`, `outcome_history`, `config_hash`, `prev_hash`,
`record_hash`) and `DecisionLog.verify_chain()`:

```python
from fivedrisk.logger import DecisionLog
print(DecisionLog("decisions.db").verify_chain())
# {'ok': True, 'checked': 3, 'skipped_pre_chain': 0, 'first_bad_id': None, 'reason': None}
```

It is **tamper evidence over a local file, not proof**: anything that can write the database
can rewrite it, and `Policy.content_hash()` is a content digest rather than a signature. Full
documentation, including what an edited row looks like and what a pass does not mean:
[`docs/audit-trail.md`](docs/audit-trail.md).

Sample audit queries and a per-signal alerting runbook: [`decision-log-cookbook.md`](decision-log-cookbook.md).

---

## Cost management primitives

Per-session token budgeting with a direct DENY at the `@gate` boundary when a reservation would exceed the session cap.

```yaml
# policy.yaml
max_session_budget_tokens: 100000   # session-level token cap
max_tool_call_budget_tokens: 4096   # per-call output cap (optional)
```

```python
from fivedrisk import gate, configure

configure(
    event_path="audit-events.ndjson",
    default_model_class="claude-sonnet-class",  # or "gpt-4-class", etc.
)

@gate(tool_name="summarize", estimated_input_tokens=2000)
def summarize_document(text: str, session_id: str) -> str:
    # Reservation is checked BEFORE this runs.
    # If projected spend > max_session_budget_tokens, raises BudgetExceededError.
    ...
```

**How admission works.**

1. At session start, `policy.admit_session(workflow_type)` validates the budget is configured. A missing cap is admitted with a warning.
2. Before each `@gate`-wrapped call, fivedrisk looks up the tool's worst-case token cost from `token_costs.py` and calls `BudgetAccumulator.reserve_for_tool_call()`.
3. If the reservation would exceed `max_session_budget_tokens`, the `@gate` raises `BudgetExceededError`. The action does not run; a `budget_intervention` NDJSON event is emitted.
4. If the reservation succeeds, the action proceeds through the normal 5D scoring path.

**Example `budget_intervention` event:**

```json
{
  "event_type": "budget_intervention",
  "timestamp": "2026-05-10T14:23:01.123Z",
  "trace_id": "a1b2c3d4-...",
  "session_id": "s1",
  "reason_code": "BUDGET_CAP_EXCEEDED",
  "cumulative_token_spend": 95000,
  "max_session_budget_tokens": 100000,
  "pressure_ratio": 0.95,
  "reserved_tokens": 8000,
  "tool_id": "call-abc",
  "tool_name": "summarize"
}
```

**What ships.** Session-level token budget cap, per-tool-call worst-case reservation, direct DENY admission, the NDJSON `budget_intervention` event, and a provider-published token cost table (OpenAI GPT-4-class, Anthropic Claude Sonnet/Opus, Google Gemini Pro, Mistral Large).

Additional operational FinOps capabilities (tool-manifest admission layers, useful-progress monitoring, multi-agent budget envelopes, wall-clock caps, retry-count caps, delegation-depth caps, historical baseline admission, post-step reconciliation) are on the roadmap.

---

## Policy configuration

```yaml
# policy.yaml

# Single-axis spike thresholds (any dimension at/above → that band).
thresholds:
  red_threshold: 4
  orange_threshold: 3

# Normalized composite-score band cutoffs. These are read ONLY from `bands:`.
# Putting them under `thresholds:` silently uses the defaults; `fivedrisk
# validate` warns if you misplace them.
bands:
  yellow_score: 1.0
  orange_score: 1.8
  red_score: 2.5

semantic_review_patterns:
  impersonation:
    - "(?i)\\bfake\\b.{0,80}\\b(public official|arrested)\\b"
  medical-claim:
    - "(?i)\\b(cures?|treats?)\\s+cancer\\b"

# Policy floors: hard minimum bands that hold regardless of the per-action
# score and cannot be lowered at runtime.
#
# For a HARD or regulated control that must ALWAYS fire, key the floor on
# tool_name ALONE. That floor is unconditional and cannot be evaded:
floor:
  - tool_name: "file_sar"            # every call to this tool is RED, no exceptions
    band: RED
    reason: "floor:sar-filing-needs-approval"

```

`command_contains` is BEST-EFFORT only: a case-sensitive substring match that
an attacker can bypass with casing, whitespace, comment splicing, or encoding.
Use it as an advisory heuristic, not a hard control. The following deliberately
warning-producing fragment is illustrative and should not be copied as a hard
policy:

```yaml
# advisory warning example — not a canonical policy.yaml
floor:
  - tool_name: "Bash"
    command_contains: "DROP TABLE"
    band: RED
    reason: "floor:advisory-destructive-sql"
```

When several floor rules fire on one action, the strictest one wins. List position does not decide a
verdict and cannot exempt an action, so a conditional floor that names no tool will fire on every
verb carrying the fields it tests, including your escalate-to-human verb. Scope every
conditional floor to the tools it is meant to govern, and see
[docs/spec/taxonomy.md](docs/spec/taxonomy.md) for how bands and floors relate.

---

## Model classes (M0-M4)

fivedrisk's `ModelClass` is an abstraction over capability, not a model name. Operators map each class to whatever model their stack supports.

| ModelClass | Class description | Example models |
|---|---|---|
| M0 | Embedding-only / classifier | OpenAI text-embedding-3, local SentenceTransformers |
| M1 | Cheap-fast inference | Claude Haiku, GPT-5-mini, Gemini Flash, local 8B (Ollama) |
| M2 | Balanced general use | Claude Sonnet, GPT-5, Gemini Pro |
| M3 | Frontier reasoning | Claude Opus, GPT-5.5, Gemini Ultra |
| M4 | Multi-model / ensemble | Operator-defined pipelines |

`ModelRouter` ships with the M0–M4 structure and tuning; model names default to `None` so you populate them for your own stack (pass your own `configs` dict to `ModelRouter(configs=...)`).

---

## Benchmark and test suite

fivedrisk ships with two offline, rerunnable measurement surfaces. Both are deterministic for the same code, inputs, interpreter, and resolved dependencies; neither requires external API calls.

**Performance benchmark** (`python benchmarks/bench_minimal.py`): measures per-action latency across the core scoring path, scanners, drift accumulator, and audit-log I/O. Reports p50/p95/p99 over 2K to 10K samples per scenario. Produces the numbers in [Performance](#performance) below.

**Attack-class benchmark** (`"$PYTHON_BIN" -I -m fivedrisk._bootstrap benchmark`): runs 39 offline expectation checks across four suites from the unified harness registry:

- **Prompt injection (14 scenarios)** — override prompts, role hijacks, system-tag injection, jailbreak markers, encoded payloads, zero-width Unicode, multi-step exfiltration.
- **Egress / output leakage (12 scenarios)** — credential, PII (SSN, credit card), crypto key, injection-echo, and exfiltration-command detection, plus post-tool allow/block checks.
- **Runtime policy (10 scenarios)** — Bash and tool-input edge cases that should allow, escalate via 5D scoring, block, or preserve session isolation.
- **Retrieved-content fixtures (3 scenarios)** — WebFetch-style safe and malicious retrieved-content cases.

The benchmark includes positive controls that should be detected, escalated, blocked, or isolated, plus negative controls that should be allowed. A 100% pass rate means observed behavior matched the scenario expectations. It does not mean open-ended adversarial robustness is proven; targeted deployment profiles, unseen cases, baseline comparison, optional observer/HITL runs, and latency/cost measurements are still required for real deployment evidence.

JSON output is available in either global or subcommand form:

```bash
"$PYTHON_BIN" -I -m fivedrisk._bootstrap --format json benchmark
"$PYTHON_BIN" -I -m fivedrisk._bootstrap --format json benchmark --include-results
```

The `--include-results` form emits one auditable result row per scenario, including its mission, expected enforcement layer, expected outcome, observed outcome, and verdict.

**AIID-style pattern smoke** (`python benchmarks/bench_aiid_patterns.py`): runs safe local checks translated from common incident-pattern classes. It compares default 5D against a targeted deployment profile and can optionally call a local Ollama observer:

```bash
"$PYTHON_BIN" benchmarks/bench_aiid_patterns.py
"$PYTHON_BIN" benchmarks/bench_aiid_patterns.py --observer ollama:gemma3:1b
```

This script is for calibration, not CI proof. It exposes which incident patterns default 5D covers, which patterns need a deployment profile, and where an observer adds value or false positives.

**Per-test-marker coverage** (`pytest -m <marker>`): pytest markers exercise dedicated control surfaces. Run any of them in isolation:

- `llm01_prompt_injection`, `llm02_insecure_output`, `llm04_model_dos`, `llm06_sensitive_disclosure`, `llm07_insecure_plugin`, `llm08_excessive_agency` — OWASP LLM Top 10 coverage. See [`owasp-llm-top10-coverage.md`](owasp-llm-top10-coverage.md).
- `asi01_goal_hijack` … `asi10_rogue_agent` — OWASP Agentic Top 10 coverage. See [`owasp-agentic-top10-coverage.md`](owasp-agentic-top10-coverage.md).
- `safety_drift` — compositional / session-level drift tests against the Markov chain.

For the full coverage map across threat catalogues see [Coverage](#coverage).

---

## Performance

Measured on Apple M1, single-thread. Rerun `benchmarks/bench_minimal.py`; absolute numbers vary with hardware, interpreter, and resolved dependencies.

| Operation | p50 | p95 | p99 |
|---|---|---|---|
| **5D core (classify + score)** | **40µs** | **41µs** | **42µs** |
| Injection scan, 30-char clean input | 11µs | 11µs | 12µs |
| Injection scan, 310-char with match | 1µs | 1µs | 1µs |
| Injection scan, 3000-char clean input | 669µs | 682µs | 685µs |
| Leakage scan, 200-char clean output | 23µs | 23µs | 23µs |
| Leakage scan, 500-char with credential | 41µs | 41µs | 42µs |
| 5D + injection + leakage scan (short input) | 64µs | 64µs | 65µs |
| 5D + Markov drift update | 43µs | 43µs | 44µs |
| 5D + SQLite audit-log write (I/O hot path) | 440µs | 545µs | 1ms |
| `@gate` sync decorator overhead (includes audit-log write) | 439µs | 744µs | 1.1ms |
| `@gate` async decorator overhead | 421µs | 559µs | 660µs |

The numbers above are fivedrisk's own, measured on the stated hardware. This project publishes no timing for any other tool: a number we did not measure under conditions we controlled is not evidence, and a side-by-side table invites a comparison this project has not earned the right to make. If you are sizing a two-stage deployment, measure your chosen semantic scanner on your own traffic.

**Caveats.** The injection scanner is linear in input length; for large RAG contexts (3000+ chars), chunk and parallelize. Run `python benchmarks/bench_minimal.py` on your target hardware for numbers that match your install.

---

## Public API stability

The following symbols are stable for the 0.x series. Breaking changes to these require a major version bump (0.x to 1.0):

- `fivedrisk.score()`
- `fivedrisk.classify_tool_call()`
- `fivedrisk.Action`
- `fivedrisk.ScoredAction`
- `fivedrisk.Band`
- `fivedrisk.Policy`
- `fivedrisk.load_policy()`
- `fivedrisk.DecisionLog`
- `fivedrisk.hooks.gate`

The framework adapters, the Claude Code hook, and the TypeScript gateway client added in 0.6.0 are stabilising; their entry-point names are expected to hold, but treat them as 0.x-provisional until 1.0.

Everything else (internal modules, undocumented helpers, future modules added in patch versions) may change between minor versions. Pin to a supported patch version (for example `fivedrisk==0.7.1`) if you embed fivedrisk into a downstream project.

---

## Architecture

```text
fivedrisk/
├── schema.py        # Band, Action, ScoredAction, HITLCard, ModelClass
├── scorer.py        # score(), model routing
├── classifier.py    # classify_tool_call() with policy baselines
├── hooks.py         # @gate, Agent SDK hooks, injection/leakage scanners
├── drift.py         # SessionAccumulator (O(1) counter-based)
├── markov.py        # MarkovDriftTracker, Gauss-Jordan, absorption probs
├── detectors.py     # Versioned detector corpus
├── policy.py        # Policy dataclass + YAML loader
├── router.py        # ModelRouter, EscalationSignal
├── logger.py        # DecisionLog (SQLite, append-only)
├── adapters.py      # to_verdict() — the shared verdict socket + band→sentinel map
├── framework_adapters.py # CrewAI / OpenAI / ADK / Pydantic AI / MS Agent Framework shims
├── claude_code.py   # Claude Code structured PreToolUse/PostToolUse hook
├── langgraph_node.py# LangGraph integration
├── gateway.py       # JSON-lines gateway for non-Python hosts
├── benchmarks.py    # 39-case offline benchmark harness
└── tests/           # regression and acceptance suite

clients/typescript/  # fivedrisk-gateway npm package (Vercel AI SDK + Genkit)
```

---

## Coverage

fivedrisk is one layer in a defence-in-depth AI governance stack. The runtime primitives map to several public threat catalogues; the coverage docs explain what fivedrisk addresses, what it partially addresses, and what is out of scope.

- **[OWASP LLM Top 10 coverage](owasp-llm-top10-coverage.md)** — pattern-detection and gating coverage for the OWASP Top 10 for LLM Applications.
- **[OWASP Agentic Top 10 coverage](owasp-agentic-top10-coverage.md)** — mapping to the OWASP Top 10 for Agentic Applications (2026).
- **[MITRE ATLAS coverage](mitre-atlas-coverage.md)** — tactic and technique mapping against MITRE ATLAS.
- **[Decision-log analysis cookbook](decision-log-cookbook.md)** — sample SQL queries against the audit log for common operational questions.

Each coverage doc names which fivedrisk primitives address which threat class and can be rerun from the pytest marker suite in a recorded environment.

---

## On the roadmap

Signalled here so contributors can see the direction. No commitment dates.

- **SPIFFE / SPIRE + MCP live reference** — an end-to-end demo of workload identity flowing through MCP into fivedrisk policy. A mock reference ships today; a live SPIRE + MCP stack is next.
- **NIST AI RMF mapping** — a coverage doc cross-referencing fivedrisk primitives to the Govern / Map / Measure / Manage functions.
- **Record-keeping field mappings** — generic field-level mappings for common governance and record-keeping frameworks, so audit exports line up with what reviewers expect.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [Loren Angoni](https://langoni.me). Contributions welcome.

> "An ambition that doesn't get executed is a hallucination."
