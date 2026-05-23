# fivedrisk — AI Agent Risk Governance Engine

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml/badge.svg)](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/fivedrisk.svg)](https://pypi.org/project/fivedrisk/)

**fivedrisk is the fast deterministic policy gate that runs before your LLM-based safety stack.**

Every AI agent action is scored on five risk dimensions, banded GREEN / YELLOW / ORANGE / RED, and resolved in 0.2 to 2.9 ms on a single CPU thread. No LLM in the decision path. No external service. No hyperscaler dependency. Apache 2.0. **Built in Vienna, Austria. Architecturally sovereign: no external services, no hyperscaler dependency, runs entirely on your own infrastructure.**

### The two-stage gate

Sequence-aware deterministic policy resolves the obvious GREEN and RED in microseconds. LLM-based scanners (LLM Guard, Lakera, Pangea) run 100 to 700 ms per check and are reserved for YELLOW and ORANGE escalation where semantic judgment actually earns its cost. In typical deployments, fivedrisk takes 90%+ of the action volume off the LLM-based scanners.

```
agent action
    │
    ▼
[fivedrisk]  ← 0.2 to 2.9 ms, deterministic, audited
    │
    ├── GREEN  ─────────────► execute
    ├── YELLOW ─► LLM scanner ──► execute / log / escalate  (100–700 ms only when needed)
    ├── ORANGE ─► HITL ────────► approve / deny
    └── RED    ─────────────► block, audit, alert
```

### What fivedrisk is

A runtime action-governance layer for AI agents. Per-action 5D scoring, HITL escalation, append-only audit log, 16-state Markov SafetyDrift for compositional attacks, identity passthrough, NDJSON event stream for SIEM. Think OPA for AI agents.

### What fivedrisk is not

A general LLM guardrail suite. A semantic content scanner. A replacement for LLM Guard, Lakera, or Pangea. A replacement for best practices in AI governance (tool and scope narrowing, prompt guardrails, system prompts). It is the deterministic pre-filter that lets those scanners and practices scale.

### Quickstart in 5 minutes

```bash
pip install fivedrisk
python -c "import fivedrisk; print(fivedrisk.__version__)"
```

Full walkthrough including scope-narrowing guidance and per-deployment tuning: [`docs/quickstart.md`](docs/quickstart.md). Copy-paste-runnable integrations: [`examples/`](examples/). Policy presets for common deployment archetypes: [`fivedrisk/policies/presets/`](fivedrisk/policies/presets/).

```python
from fivedrisk.hooks import gate

@gate(tool_name="write_to_database", autonomy_context=2)
async def write_record(table: str, data: dict) -> None:
    ...  # only executes if 5D scores GREEN or YELLOW
         # ORANGE → human approval required
         # RED    → blocked, never runs
```

![fivedrisk demo — injection blocked, rm -rf stopped, SafetyDrift escalation](https://github.com/user-attachments/assets/5d6b9631-c36b-4674-bd3f-3897555f26f8)

---

## What it does

fivedrisk scores every AI agent action on **5 risk dimensions** (0–4 each):

| Dimension | What it measures |
|---|---|
| **D** — Data Sensitivity | Public → PII → financial → credentials |
| **T** — Tool Privilege | Read-only → write → admin → destructive |
| **R** — Reversibility | Undoable → hard-to-undo → irreversible |
| **E** — External Impact | Local → internal API → external → untrusted |
| **A** — Autonomy Context | User-direct → agent-supervised → fully autonomous |

5D stays deterministic. Bands signal what fivedrisk wants your stack to do; your stack chooses the LLM and the workflow.

**Default 3-band experience:**

- **GREEN** — execute, normal logging. Most actions land here.
- **ORANGE** — human-in-the-loop approval required. fivedrisk signals; your stack handles the LLM choice (human reviewer, AI-assisted HITL pipeline, escalation workflow, whatever fits). fivedrisk does not auto-promote the model class for ORANGE.
- **RED** — blocked. Hard gate or dual control.

**Opt-in 4-band compliance mode** (regulated / audit-shaped deployments):

Set `enable_yellow_band: true` in `policy.yaml` to surface a moderate-risk tier between GREEN and ORANGE. YELLOW is the cost-management band: stable band label for audit queries, enhanced logging, no human approval needed. Useful when audit dashboards or quarterly reports need to track moderate-risk decisions as a population without writing score-range queries that break when policy thresholds tune.

Within YELLOW, model-class promotion for sensitive data (D2/D3) is a separate opt-in: `yellow_model_escalation: true` adds the routing recommendation. The caller's stack still decides whether to honour it.

fivedrisk is one layer in a defence-in-depth AI governance stack. It scores actions and emits decisions; your stack composes those decisions with your model routing, your HITL workflow, your incident response, and any upstream sensors you operate.

---

## Features

- **5D scoring engine** — deterministic, ~40µs per action (p50) on M1, no LLM calls. See [Performance](#performance) below for full numbers
- **Markov SafetyDrift** — 16-state Markov chain detects cumulative risk across action sequences; catches compositional attacks that individual scoring misses
- **Session accumulator** — O(1) counter-based drift tracking for the common case
- **Injection scanner** — 24+ regex patterns covering GPT-5/Opus-era evasion (Base64, zero-width Unicode, role hijacks, encoded exec calls)
- **Output leakage scanner** — PII, credentials, crypto keys, injection-echo detection
- **`@gate` decorator** — wrap any sync or async function with full 5D gating
- **Agent SDK hooks** — `fivedrisk_pre_tool` / `fivedrisk_post_tool` for Anthropic Agent SDK
- **LangGraph node** — drop-in integration for LangGraph pipelines
- **Destination policy** — allowlist/denylist for outbound endpoints
- **Audit log** — append-only SQLite decision log plus optional NDJSON event stream for SIEM delivery; every action recorded
- **Policy floor enforcement** — floor rules in `policy.yaml` cannot be overridden at runtime
- **Defence-in-depth test suite** — see [Benchmark and test suite](#benchmark-and-test-suite) below for the full list of attack-class coverage
- **424 tests** with 0 failures

---

## Install

```bash
pip install fivedrisk

# With LangGraph integration
pip install "fivedrisk[langgraph]"
```

Or from source (latest main):
```bash
pip install git+https://github.com/theDoc001/fivedrisk.git
pip install "git+https://github.com/theDoc001/fivedrisk.git#egg=fivedrisk[langgraph]"
```

---

## Quick start (30 seconds)

```python
from fivedrisk import classify_tool_call, score, load_policy, Band

policy = load_policy("policy.yaml")  # or use defaults
action = classify_tool_call("Bash", {"command": "rm -rf /tmp/cache"}, policy)
result = score(action, policy)

print(result.band)                     # Band.ORANGE
print(result.rationale)                # "ORANGE — Bash: Reversibility=3 (≥ ORANGE threshold 3)"
print(result.routing.approval_required) # True. Your HITL stack handles the rest.
```

**With the `@gate` decorator:**
```python
from fivedrisk.hooks import gate, configure
from fivedrisk import load_policy

configure(policy=load_policy("policy.yaml"))

@gate(tool_name="send_email", autonomy_context=1)
def send_email(to: str, body: str) -> None:
    # only executes if 5D scores GREEN or YELLOW
    smtp.send(to, body)
```

**With Anthropic Agent SDK:**
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

## SafetyDrift — why sequence risk matters

A single READ of a config file scores GREEN. But 10 GREENs followed by a write to an external API using credentials extracted two steps earlier is a RED sequence. Most tools miss this.

fivedrisk tracks cumulative session state via a **16-state Markov chain** over `(data_exposure_tier × activity_risk_tier)`. When absorption probability into a dangerous state crosses 0.3, the next action is escalated to ORANGE. At 0.7, it's escalated to RED.

```python
from fivedrisk.markov import MarkovDriftTracker, make_default_transition_matrix

tracker = MarkovDriftTracker(make_default_transition_matrix(), session_id="abc")
bump = tracker.record(scored_action)
if bump:
    print(f"Drift: {bump.reason}, escalated to {bump.escalated_band}")
```

---

## Policy configuration

```yaml
# policy.yaml
thresholds:
  red_threshold: 4
  orange_threshold: 3
  orange_score: 1.8
  yellow_score: 1.0

[floor]
# These rules block regardless of per-action score
- tool_name: "Bash"
  command_contains: "DROP TABLE"
  band: RED
  reason: "floor:no-destructive-sql"
```

---

## Benchmark and test suite

fivedrisk ships with two reproducible measurement surfaces. Both are deterministic, safe to run in CI, and require no external API calls.

**Performance benchmark** (`python benchmarks/bench_minimal.py`): measures per-action latency across the core scoring path, scanners, drift accumulator, and audit-log I/O. Reports p50/p95/p99 over 2K to 10K samples per scenario. Used to publish the numbers in [Performance](#performance) above.

**Attack-class benchmark** (`python -m fivedrisk benchmark`): runs 39 offline attack scenarios across three categories:

- **Prompt injection (12 scenarios)** — pattern-detection coverage for override prompts, role hijacks, system-tag injection, jailbreak markers, encoded payloads, zero-width Unicode, and multi-step exfiltration.
- **Output leakage (8 scenarios)** — credential, PII (SSN, credit card), crypto key, injection-echo, and exfiltration-command detection in model outputs.
- **Runtime tool misuse (19 scenarios)** — Bash and tool-input edge cases that should escalate via 5D scoring or `@gate` enforcement.

**Per-test-marker coverage** (`pytest -m <marker>`): pytest markers exercise dedicated control surfaces. Run any of them in isolation:

- `llm01_prompt_injection`, `llm02_insecure_output`, `llm04_model_dos`, `llm06_sensitive_disclosure`, `llm07_insecure_plugin`, `llm08_excessive_agency` — OWASP LLM Top 10 coverage. See [`owasp-llm-top10-coverage.md`](./owasp-llm-top10-coverage.md).
- `safety_drift` — compositional / session-level drift tests against the Markov chain.

For the full coverage map across threat catalogues see the [Coverage](#coverage) section below.

---

## Performance

Measured on Apple M1, single-thread. Numbers reproducible from `benchmarks/bench_minimal.py`.

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

External optional layers (not in fivedrisk, integration only):

- [PromptArmor](https://promptarmor.com): ~20-30ms typical (network round-trip)
- [LLM Guard](https://llm-guard.com) token-based scanners: ~10-15ms typical
- [LLM Guard](https://llm-guard.com) ML-based scanners: ~50-200ms typical

**Caveats:**

- The injection scanner is linear in input length; for large RAG contexts (3000+ chars), chunk and parallelize.
- Run `python benchmarks/bench_minimal.py` on your target hardware for numbers that match your install.

---

## Audit log

fivedrisk produces an append-only decision log entry for every agent action. Each entry records:
- Risk band and rationale
- Dimension scores (all 5 axes)
- Model routing decision and approval history
- Session drift state
- Injection and leakage scan results
- Optional agent identity claim (see below)

### Agent identity passthrough

fivedrisk accepts opaque agent identity claims through `Action.metadata["agent_identity"]`. The string flows through unchanged into the audit log, where SOC and SIEM tools can correlate decisions by issuer, subject, or workload URI. SVID, JWT, and X.509 subject DN strings are all supported as opaque data today.

```python
from fivedrisk import classify_tool_call, score

action = classify_tool_call("Bash", {"command": "rm -rf /tmp/cache"})
action.metadata["agent_identity"] = "spiffe://example.org/agents/triage-bot"
result = score(action)
# audit log entry now carries the identity string verbatim
```

Cryptographic validation, structured parsing (JWT claim extraction, X.509 chain verification), and identity-aware policy hooks are post-OSS scope. Tracked as `OSS-AGENT-ID-PASSTHROUGH-001` in the backlog.

### Reserved metadata keys

Some keys in `Action.metadata` have reserved semantics. Do not overwrite them with arbitrary values:

- `agent_identity` — opaque identity claim string (see above).

This list will grow over time. Other keys you set on `Action.metadata` are passed through unchanged.

---

## Identity capture

`Action.acting_identity` is a typed pass-through primitive for the principal an action is being taken on behalf of. Distinct from `agent_identity` (the AI agent's own workload identity) — `acting_identity` is who authorized the action.

```python
from fivedrisk import gate, ActingIdentity, PrincipalType, AttestationSource

# Decorator default applies unless caller overrides per-call
@gate(tool_name="approve_invoice", acting_identity=ActingIdentity(
    principal_id="svc-payroll",
    principal_type=PrincipalType.SERVICE,
    attestation_source=AttestationSource.JWT_CLAIM,
    roles=["finance.approve"],
))
def approve_invoice(invoice_id: str, session_id: str) -> None:
    ...

# Per-call override via _fivedrisk_acting_identity kwarg
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
# policy.yaml
identity_required: true
```

**What ships.** Opaque pass-through capture of `principal_id`, `principal_type` (USER / SERVICE / ROLE / AGENT / ANONYMOUS), `attestation_source` (HTTP_HEADER / JWT_CLAIM / ENV_VAR / AGENT_DECLARED / NONE), optional `roles` and `data_scope`. The fields flow through to the audit log and NDJSON events unchanged. Identity-aware policy evaluation beyond the `identity_required` admission check, cryptographic validation, and SPIFFE/SPIRE native binding are on the project roadmap.

---

## Cost management primitives

Per-session token budgeting with direct DENY at the @gate boundary when a reservation would exceed the session cap.

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

1. At session start, `policy.admit_session(workflow_type)` validates the budget is configured. Missing cap is admitted with a warning.
2. Before each `@gate`-wrapped call, fivedrisk looks up the tool's worst-case token cost from `token_costs.py` and calls `BudgetAccumulator.reserve_for_tool_call()`.
3. If the reservation would exceed `max_session_budget_tokens`, the @gate raises `BudgetExceededError`. The action does not run; a `budget_intervention` NDJSON event is emitted.
4. If the reservation succeeds, the action proceeds through the normal 5D scoring path.

**Example NDJSON budget_intervention event:**

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

**What ships in OSS.** Session-level token budget cap, per-tool-call worst-case reservation, direct DENY admission, NDJSON budget_intervention event, provider-published token cost table (OpenAI GPT-4-class, Anthropic Claude Sonnet/Opus, Google Gemini Pro, Mistral Large).

Additional Operational FinOps capabilities (Tool Manifest pattern for further admission layers, useful-progress monitoring, multi-agent budget envelopes, wall-clock caps, retry-count caps, delegation-depth caps, historical baseline admission, post-step reconciliation) are on the project roadmap.

---

## Architecture
```text
fivedrisk/
├── schema.py        # Band, Action, ScoredAction, HITLCard, ModelClass
├── scorer.py        # score(), model routing (§12-19)
├── classifier.py    # classify_tool_call() with policy baselines
├── hooks.py         # @gate, Agent SDK hooks, injection/leakage scanners
├── drift.py         # SessionAccumulator (O(1) counter-based)
├── markov.py        # MarkovDriftTracker, Gauss-Jordan, absorption probs
├── detectors.py     # Versioned detector corpus (2026-04-14.2)
├── policy.py        # Policy dataclass + YAML loader
├── router.py        # ModelRouter, EscalationSignal
├── logger.py        # DecisionLog (SQLite, append-only)
├── langgraph_node.py# LangGraph integration
├── benchmarks.py    # 39-case offline benchmark harness
└── tests/           # 424 tests
```


---

## Coverage

fivedrisk is one layer in a defence-in-depth AI governance stack. The runtime primitives map to several public threat catalogues and regulatory frameworks; the coverage docs explain what fivedrisk addresses, what it partially addresses, and what is out of scope.

- **[OWASP LLM Top 10 coverage](./owasp-llm-top10-coverage.md)** — pattern-detection and gating coverage for the OWASP Top 10 for LLM Applications.
- **[OWASP Agentic Top 10 coverage](./owasp-agentic-top10-coverage.md)** — mapping to OWASP Top 10 for Agentic Applications (2026).
- **[MITRE ATLAS coverage](./mitre-atlas-coverage.md)** — tactic and technique mapping against MITRE ATLAS v5.4.0.
- **[Decision log analysis cookbook](./decision-log-cookbook.md)** — sample SQL queries against the audit log for common operational and compliance questions.

Each coverage doc names which fivedrisk primitives address which threat-class and is reproducible from the pytest marker suite.

---

## Planned

Future capability surfaces signalled here so they show up in search and so contributors know what to expect. No commitment dates.

- **SPIFFE / MCP reference example** — end-to-end demo of workload identity flowing through MCP into fivedrisk policy. Mock reference today; live SPIRE+MCP stack later.
- **MITRE ATLAS coverage with real tests** — same pattern as the OWASP LLM Top 10 doc that shipped in v0.4.0. pytest markers per ATLAS technique, reproducible coverage matrix.
- **NIST AI RMF mapping** — coverage doc cross-referencing fivedrisk primitives to subcategories of Govern, Map, Measure, Manage.
- **OWASP Agentic Top 10 coverage** — companion doc to the OWASP LLM Top 10 coverage. v0.5.0 work.
- **Regulatory crosswalks** — record-keeping field mappings for AI Act Article 12, NIS2, DORA ICT-incident reporting, ISO 42001.
- **Decision log analysis cookbook** — sample SQL queries against the audit trail for common compliance questions (filter by band, by reviewer, by session drift, etc.).

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [Loren Angoni](https://langoni.me). Contributions welcome.

> "An ambition that doesn't get executed is a hallucination."
