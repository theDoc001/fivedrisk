# 5D Risk Governance Engine — Architecture Mapping

**Maps**: Governance Spec v0.3 (§12-19) → `fivedrisk/` code → backlog
**Updated**: 2026-04-13
**Version**: 0.3.0

---

## Spec Coverage Matrix

| Spec Section | What it defines | Status | Code location | Notes |
|---|---|---|---|---|
| §12.1 Objective | Action Risk Engine purpose | ✅ DONE | `schema.py`, `scorer.py` | |
| §12.2 Risk Dimensions | 5 dimensions (D/T/R/E/A), 0-4 scale | ✅ DONE | `schema.py:Action` | |
| §12.3 Risk Score Formula | Weighted composite | ✅ DONE | `scorer.py:score()` | Normalized to 0-3 |
| §12.4 Risk Bands | Green/Yellow/Orange/Red | ✅ DONE | `schema.py:Band` | Was 3-band, now 4-band |
| §12.5 Control Mapping | Model/Approval/Logging per band | ✅ DONE | `scorer.py:_route_model()` | Routing integrated |
| §12.6 Example Scoring | 4 worked examples | ✅ DONE | `tests/golden_set/` | 10 scenarios |
| §12.7 Implementation Notes | Pre-tool, deterministic, attached | ✅ DONE | `classifier.py`, `scorer.py` | |
| §13 Execution Sandbox | S0-S4 sandbox classes | ❌ BACKLOG | — | Needs Docker integration |
| §13.5 Credential Broker | Scoped short-lived tokens | ❌ BACKLOG | — | Phase 5+ |
| §13.6 Network Policies | Deny-all, allowlist | ❌ BACKLOG | — | Docker network policy |
| §14 Memory Trust Scoring | Trust dims, poisoning detection | ❌ BACKLOG | — | Phase 5, needs KB |
| §15.2 Intervention Actions | Stop/Pause/Resume/Redo | ⚠️ PARTIAL | — | Discord bot has stop |
| §15.4 HITL Control Cards | Card schema, UX principles | ✅ DONE | `schema.py:HITLCard` | Schema only, no UI |
| §15.5 Intervention Logging | Who/what/when/state | ✅ DONE | `logger.py:DecisionLog` | |
| §15.7 Three User Levers | Prompt/Cost/Risk | ⚠️ PARTIAL | `router.py` | Cost lever needs UI |
| §16 Cost × Risk Coupling | Rules A-E, matrix | ✅ DONE | `scorer.py`, `router.py` | Enforced in routing |
| §17 TEVV Test Packs | 9 test packs | ⚠️ PARTIAL | `tests/` | 84 tests, need adversarial |
| §18 Agent Identity | Lifecycle, delegation, anomaly | ❌ BACKLOG | — | Phase 5+ |
| §19.1-19.2 Model Classes | M0-M4 abstract classes | ✅ DONE | `schema.py:ModelClass` | |
| §19.3 Routing Table | Data×Risk×Task → Model | ✅ DONE | `scorer.py:_route_model()` | |
| §19.5 Allowed/Disallowed | No M0/M1 for Orange/Red | ✅ DONE | `router.py:ModelRouter` | |
| §19.6 Routing Decision Object | JSON structure | ✅ DONE | `schema.py:RoutingDecision` | |
| §19.7 Audit + Explainability | Why model was selected | ✅ DONE | `RoutingDecision.reason` | |

**Coverage**: 14/21 sections fully implemented, 3 partial, 4 backlogged.

---

## New in v0.3.0

### Injection Scanner (`hooks.py:scan_input_for_injection`)
L1 prompt injection defense. 24 regex patterns covering: override attempts, role hijacks,
system tag injection, jailbreak keywords, multi-step decomposition signals, credential
exfiltration, encoding/obfuscation (Base64, zero-width Unicode, Unicode escape chains).
Zero external dependencies. Call before any LLM invocation.

### Output Leakage Scanner (`hooks.py:scan_output_for_leakage`)
Enhanced egress scanner: credentials, PII (SSN, credit card), crypto keys, injection-echo
detection (model repeats injection triggers = model was corrupted), and exfiltration command
patterns. Call after receiving any LLM response, before acting on it.

### @gate Decorator (`hooks.py:gate`)
Wrap any Python function with full 5D scoring:
```python
from fivedrisk.hooks import gate

@gate(tool_name="write_vault_file", autonomy_context=1)
def write_to_vault(path: str, content: str) -> None:
    Path(path).write_text(content)

# Async functions work too:
@gate(tool_name="send_discord_message", autonomy_context=0)
async def send_message(channel_id: int, text: str):
    ...
```
The decorated function is gated through the 5D engine before execution.
If the action scores ORANGE or RED, the function is NOT called and either
`on_block()` is invoked or `ValueError` is raised. Works for sync and async functions.

### Rate Limiting / DoS Defense (`hooks.py:rate_limit_check`)
- Sliding window: >120 actions per 60s → block
- Burst detection: >30 actions in 10s → throttle
- HITL queue depth: if >20 pending cards → refuse new actions until queue drains

### SafetyDrift MVP — Session Accumulator (`drift.py`)
Tracks cumulative risk across action sequences:
- Data classes accessed (D0-D3) — catches cross-classification exfiltration
- External endpoint contacts — catches reconnaissance patterns
- Irreversible operation count — catches destructive sequences
- Privilege ceiling tracking — catches escalation patterns
- Green runway detection — catches stealth (long GREEN streak masking accumulation)

O(1) per action, no Markov math. 18 tests covering all 5 attack scenarios.
Full Markov chain planned for 5D Standard tier.

### Runtime Wiring
- `builder.py`: injection scan on goal objective before LLM, egress scan on output before vault write
- `planner.py`: auto-approve permanently removed — HITL always required (P-004)
- `/approve` command now accepts optional instructions parameter

---

## Where 5D Activates — Action Flow Map

### Flow 1: Dot reads a file it can't open
```
User shares file → Dot receives → Read tool (GREEN, sub-ms)
  → Dot searches for extension handler → Grep/WebSearch (GREEN, sub-ms)
  → Dot finds it needs a package → pip install (YELLOW, classifier bumps tool_privilege)
  → 5D check: pip install from unknown source → ORANGE → HITL card
  → User approves → remember "pip install <package>" for project → GREEN next time
```

### Flow 2: Dot looks up web information
```
User asks research question → Dot plans WebSearch + WebFetch
  → WebSearch (GREEN) → WebFetch (GREEN)
  → PostToolUse hook scans output for injection patterns
  → If clean: content enters context as data (never instruction)
  → If injection detected: flag in context + 5D bumps next action's data_sensitivity
```

### Flow 3: Prompt injection via website
```
Dot reads webpage → PostToolUse detects "ignore instructions" pattern
  → Content marked as untrusted in metadata
  → Dot's next action based on that content → classifier bumps data_sensitivity +1
  → If Dot tries rm -rf based on injected instruction:
    → classifier: tool_privilege=4, reversibility=4 → RED → STOP
  → Injection succeeded at LLM level, 5D blocked at execution level
```

### Flow 4: Dot executes a spec/plan (many actions)
```
Builder picks up task list → for each task:
  → 5D scores (sub-ms, pure computation)
  → First 3 GREENs: full scoring + log
  → After 3 consecutive GREEN for same tool: batch-approve mode
    (still logged, score cached by tool_input_hash, no content scan)
  → If pattern changes (new tool, different input hash): full scoring resumes
  → If any action hits YELLOW+: exits batch mode
```

### Flow 5: Builder retries after failure
```
Attempt 1: action → 5D GREEN → execute → fails
Attempt 2: different approach → new hash → fresh 5D score
  → If score escalated (higher band): flag in HITL card
Attempt 3: another approach → 5D score
  ...
Attempt 5 (budget exhausted): HITL card type "retry-exhausted"
  → Shows: all 5 attempts with scores, failure reasons
  → Actions: "Provide new prompt" | "Approve riskier approach" | "Kill task"
```

---

## Model Routing Chain

```
┌─────────────────────────────────────────────────────────────┐
│ phi-4-mini (M0)                                             │
│ • Task classification (complexity/domain/reasoning 1-5)     │
│ • If any dimension > 3 → ESCALATE to Qwen                 │
│ • Capability ceiling: lookup, parsing, routing only         │
│ • Speed: ~25 tok/sec local                                  │
└────────────────────┬────────────────────────────────────────┘
                     │ ESCALATE
┌────────────────────▼────────────────────────────────────────┐
│ Qwen3:8b (M1/M2)                                           │
│ • Planning, drafting, routine execution                     │
│ • /think mode for multi-step reasoning (M2)                │
│ • Self-evaluates confidence: HIGH/MEDIUM/LOW                │
│ • If LOW or 5D band ORANGE+ → ESCALATE to Sonnet          │
│ • Capability ceiling: complex reasoning, math, advanced code│
│ • Speed: local, ~15 tok/sec                                │
└────────────────────┬────────────────────────────────────────┘
                     │ ESCALATE
┌────────────────────▼────────────────────────────────────────┐
│ Sonnet 4.6 + Opus Advisor (M3)                              │
│ • Sonnet executes, calls Opus mid-task for guidance         │
│ • Advisor Tool: server-side, no extra roundtrip             │
│ • API: anthropic-beta: advisor-tool-2026-03-01              │
│ • Advisor: 400-700 tokens guidance per call, max 3/request  │
│ • Near-Opus quality at lower total cost                     │
│ • 5D scores each action, Opus advises on ORANGE decisions   │
│ • Capability ceiling: Red-tier decisions, trusted control    │
└────────────────────┬────────────────────────────────────────┘
                     │ RED-tier only
┌────────────────────▼────────────────────────────────────────┐
│ Opus 4.6 (M4)                                               │
│ • Trusted control plane                                     │
│ • Red-band review + dual control                            │
│ • Direct API call (not advisor pattern)                     │
│ • Used for: credential operations, production deploy review,│
│   legal/financial review, security-sensitive decisions       │
│ • Never used for routine work (cost constraint §16 Rule D) │
└─────────────────────────────────────────────────────────────┘
```

### Advisor Tool Integration (Anthropic API)

```python
# In orchestration layer, when routing selects M3:
import anthropic

client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=8192,
    extra_headers={"anthropic-beta": "advisor-tool-2026-03-01"},
    tools=[{
        "type": "advisor_20260301",
        "name": "advisor",
        "model": "claude-opus-4-6",
        "max_uses": 3,
        "caching": {"type": "ephemeral", "ttl": "5m"},
    }],
    messages=[{"role": "user", "content": task_prompt}],
)
# Sonnet auto-calls advisor when stuck or before major decisions
# Advisor result included in response.content as advisor_tool_result blocks
# Billing: iterations[] shows per-model breakdown
```

---

## HITL Card Type System

| Card Type | When | Band | Default Actions |
|---|---|---|---|
| `planner-clarification` | Planner needs user input on scope | YELLOW | Respond / Skip |
| `5d-risk-gate` | Action exceeds GREEN band | ORANGE/RED | Approve / Deny / Modify |
| `builder-error` | Build step failed | YELLOW | Retry / Skip / New prompt |
| `retry-exhausted` | 5 attempts failed | ORANGE | New prompt / Approve riskier / Kill |
| `model-escalation` | Agent hit capability ceiling | YELLOW | Approve cloud / Stay local |
| `cost-threshold` | Spend approaching budget | YELLOW | Continue / Trim scope / Stop |

### Card Structure (Discord embed)
```
┌─────────────────────────────────────────┐
│ 🟠 ORANGE — Docker restart requires     │
│ approval                                │
│                                         │
│ Dot wants to restart the LangGraph      │
│ container. This affects running services.│
│                                         │
│ [Approve] [Deny] [Approve & Remember]   │
│                                         │
│ ▼ Details                               │
│   5D Score: TP=3 R=2 EI=1 DS=0 AC=2    │
│   Composite: 7.6 | Normalized: 1.07    │
│   Model: Sonnet+Advisor (M3)            │
│   Similar past decisions: 3 approved    │
│                                         │
│   ☐ Remember for this project           │
│   ☐ Remember for all projects           │
└─────────────────────────────────────────┘
```

---

## Backlog Items (from spec gaps)

| ID | Section | What's missing | Priority | Phase |
|---|---|---|---|---|
| FEAT-5D-SANDBOX | §13 | Execution sandbox classes S0-S4 | HIGH | 5 |
| FEAT-5D-CRED-BROKER | §13.5 | Credential broker pattern | HIGH | 5 |
| FEAT-5D-NETWORK | §13.6 | Network deny-all + allowlist | MEDIUM | 5 |
| FEAT-5D-MEM-TRUST | §14 | Memory trust scoring | MEDIUM | 5+ |
| FEAT-5D-MEM-POISON | §14.5 | Poisoning detection | MEDIUM | 5+ |
| FEAT-5D-HITL-UI | §15.4 | Discord HITL card rendering | HIGH | 4 |
| FEAT-5D-HITL-ACTIONS | §15.2 | Full intervention action set | MEDIUM | 4+ |
| FEAT-5D-TEVV-INJECT | §17.2 | Prompt injection test pack | HIGH | 4 |
| FEAT-5D-TEVV-EXFIL | §17.3 | Data exfiltration test pack | HIGH | 4 |
| FEAT-5D-TEVV-BYPASS | §17.4 | Approval bypass test pack | HIGH | 4 |
| FEAT-5D-IDENTITY | §18 | Agent identity lifecycle | LOW | 5+ |
| FEAT-5D-GEO | §19.4 | Geography-aware routing | LOW | Enterprise |
| FEAT-5D-BATCH | perf | Batch-approve consecutive GREENs | MEDIUM | 4 |
| FEAT-5D-HEARTBEAT | UX | 10s routing progress indicator | MEDIUM | 4 |

---

## Execution Failure Post-Mortem (2026-04-11)

**What happened**: Built 3-band GO/ASK/STOP engine without reading governance spec v0.3 which defines a 4-band GREEN/YELLOW/ORANGE/RED system with sandbox classes, credential broker, memory trust, Cost×Risk coupling, and model routing.

**Root cause**: Skipped existing knowledge (P-009 violation: didn't shop before building).

**Fix applied**: Upgraded to 4-band system, added model routing, HITL cards, decision memory, Cost×Risk coupling. 84 tests passing.

**Systemic fix**: Add pre-build check to Coach: "Has this been specced? Read the spec first." Log as principle violation in decision log.

---

## New Principle: P-011 Escalate Don't Guess

> When an agent recognizes a task is beyond its capability ceiling, it
> escalates to a more qualified model rather than attempting and failing.
> Escalation is cheap. Bad output is expensive.
>
> Applies to: phi→Qwen, Qwen→Sonnet, Sonnet→Opus.
> Signals: low confidence, high complexity, high reasoning depth, ORANGE+ 5D band.
> Each model has an explicit ceiling defined by task classification.
