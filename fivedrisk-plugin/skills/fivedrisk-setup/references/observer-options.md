# Observer design options

An observer is an optional semantic signal beside deterministic 5D controls. This skill
helps design one; the public fivedrisk runtime does not ship a production observer-LLM or
TypeSafe Jev integration. The repository's Ollama observer is benchmark-only.

## Non-negotiable precedence

Use this fusion rule:

`final severity = max(deterministic severity, semantic escalation)`

- RED or another hard deterministic floor denies immediately. An observer cannot review
  it downward.
- ORANGE remains approval-required. An observer may escalate it to denial, never approve
  it for execution.
- Invoke the observer only for ambiguity classes named in the confirmed profile.
- An observer “allow” means no semantic escalation; it is never execution permission.
- Timeout, malformed output, unavailability, exhausted budget, or uncalibrated thresholds
  route to human approval, or block when no real approval channel exists.
- With no observer, a configured semantic-review cue routes to human approval or blocks;
  it does not execute.

The runtime's `semantic_review_patterns` are deterministic regular expressions. They are
not a semantic model and must not be presented as one.

## Choices

### Deterministic 5D only (`none`)

Lowest operational complexity. Appropriate when tools, data, destinations, and action
classes can be expressed with deterministic controls. Ambiguities must be reviewed by a
human or blocked.

### General observer LLM (`general_llm`)

Can judge narrowly described ambiguity classes that deterministic rules cannot express
well. Define a strict response schema, allow no direct tool authority, and measure
calibration, failures, latency, cost, and escalation quality before relying on it.

### TypeSafe Jev (`typesafe_jev`)

Use a small typed `Noul`, `Choice`, or `Score` judgment with explicit probabilities.
Application code—not the model—owns routing, precedence, thresholds, and fail-closed
behavior. Independent judgments can be batched in one request. Typed output is not proof
of correctness, and thresholds remain `uncalibrated` until evaluated on representative
deployment cases.

For example, this optional design asks one narrow yes/no question. It is not bundled or
called by fivedrisk:

```python
from typesafe_sdk import Noul, NoulCriteria, TypeSafeClient

with TypeSafeClient() as client:
    response = client.system_one(
        state={"tool": tool_name, "arguments": redacted_arguments},
        questions={
            "requires_escalation": Noul(
                instructions="Does this action require semantic escalation?",
                criteria=NoulCriteria(
                    true="The action has an ambiguity that requires stricter handling.",
                    false="No named semantic ambiguity is present.",
                ),
            )
        },
    )

probability = response.answers["requires_escalation"].noul
semantic_escalation = "RED" if probability >= 0.90 else "ORANGE" if probability >= 0.55 else None
final_severity = max_severity(deterministic_severity, semantic_escalation)
```

Application code owns the threshold, the severity mapping, and `max_severity`; the
example thresholds are placeholders. Calibrate them on representative labeled deployment cases,
record false allows and unnecessary escalations, and keep the state
minimal and redacted. Wrap the call so timeout, API error, malformed output, or missing
credentials route to human approval or block as specified above. Never send secrets or
raw system prompts merely to make the observer work.

## Security, latency, and compute claims

Deterministic-first routing can avoid a semantic inference call for non-routed actions.
Routed actions add inference latency, compute, possible retries, and sometimes human
review. Jev can batch independent questions, which may reduce request count. Do not claim
a percentage saving, faster response, lower API cost, better accuracy, or improved
security without measuring observer call rate, p50/p95/p99 latency, token or compute
cost, goodput, errors, misses, and escalations for this deployment.

## Host packaging boundary

The plugin follows Agent Plugins 1.0 with a root `plugin.json`, a schema-specific
`.codex-plugin/plugin.json` compatibility manifest, and the auto-discovered `skills/`
directory. OpenAI presentation metadata and onboarding are declared in the root extension;
the compatibility manifest carries the same onboarding path. On ChatGPT, Codex, and other
portable hosts the public ZIP advises and emits reviewable configuration; ordinary
skill execution does not gate tool calls.

Lifecycle hooks are available for manual Codex desktop plugins and Claude Code plugins
when supported by that host. Protocols are host-specific: this release's separate manual
ZIP contains the reviewed Claude-specific integration, not a Codex hook adapter. A ZIP
containing lifecycle hooks is not eligible for the public plugin directory. Submit only
the hooks-free public ZIP; publishing it on GitHub does not mean directory approval.
Add MCP only if the product later needs live authenticated data, actions, or persistence;
this consulting flow does not.

Official references:

- OpenAI plugin structure: <https://developers.openai.com/plugins/build/plugins>
- OpenAI skills in plugins: <https://developers.openai.com/plugins/concepts/skills>
- OpenAI guidance for Claude plugin conversion:
  <https://developers.openai.com/plugins/guides/submit-claude-plugin>
- TypeSafe documentation: <https://docs.typesafe.ai/llms.txt>
