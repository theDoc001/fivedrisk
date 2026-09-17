# fivedrisk taxonomy — bands and dispositions (canonical)

**Status:** canonical. This is the single source of truth for what fivedrisk's
verdict vocabulary means. Code (the `Band` enum, `@gate`/hook semantics, the
plugin mappers) and docs conform to this file. For *what question a verdict
answers* — the security/blast-radius scope of the assessment, and what fivedrisk
deliberately does not grade — see `scope.md`.

The verdict model has been described three different ways across the codebase's
history. That drift was
itself a defect — it confused readers and reviewers. There is exactly one model,
below.

---

## Two distinct axes: BAND (what) vs DISPOSITION (what to do)

fivedrisk separates **severity classification** from **operational routing**.
Conflating them is the mistake this doc exists to prevent.

### BAND — the audit-stable severity verdict

The `Band` enum (`fivedrisk.schema.Band`) is the deterministic per-action
severity. Exactly four values, ordered:

| Band | Meaning |
|---|---|
| `GREEN` | Low risk. Nothing about the action crosses an elevated threshold. |
| `YELLOW` | Moderate risk. Opt-in tier (`enable_yellow_band: true`); otherwise folded into GREEN. |
| `ORANGE` | High risk. Consequential enough that a deployment should not run it unattended. |
| `RED` | Severe risk. The most serious classification fivedrisk assigns. |

Each row states **severity only**. Earlier revisions of this table described ORANGE
as "needs human approval" and RED as "the action is denied" — those are the *default
dispositions* for those bands, not the bands' meaning, and stating them here
contradicted this section two tables further down. They are overridable per
deployment, so a reader who took them as guarantees was reading a promise this
layer does not make. The mapping lives in **Default band → disposition** below, and
that is the only place it is stated.

Bands are stable audit labels. `str(Band.RED) == "RED"`. They are **not** routing
targets — a band does not by itself say "send this to the HITL queue" or "escalate
the model." That is the disposition's job.

### DISPOSITION — the deployer's routing ladder

A **disposition** is what a deployment *does* with a banded action. The ladder:

| Disposition | Meaning |
|---|---|
| `EXECUTE` | Run the action, normal logging. |
| `LOG_ELEVATED` | Run, but log with full rationale + dimension scores + routed model. |
| `ROUTE_OBSERVER` | Run, but mirror to an observer/secondary-review channel. |
| `ROUTE_HITL` | Hold; require a human approve/deny before running. |
| `BLOCK` | Deny; never run. |

### Default band → disposition mapping

The shipped defaults:

| Band | Default disposition |
|---|---|
| `GREEN` | `EXECUTE` |
| `YELLOW` | **`LOG_ELEVATED`** (run + enhanced logging; no HITL by default) |
| `ORANGE` | `ROUTE_HITL` (approval required) |
| `RED` | `BLOCK` |

**YELLOW's default disposition is `LOG_ELEVATED`**, not HITL. Deployers may override
YELLOW per policy (`log_only`, `escalate_to_orange`, or a custom callback), and may
insert `ROUTE_OBSERVER` for any band. The band never changes; only the disposition
a deployment attaches to it does.

### A floor rule is a BAND, not a disposition

`floor:` rules — the things variously called floor rules or red lines — sit on the
band axis, and only on it. **A floor rule sets a MINIMUM band for a matching action.**
It does not deny the action, it does not route it, and it does not name a
disposition; what happens next is whatever the deployment maps that band to.

Two consequences worth stating, because the informal name invites the other reading:

- **"Red line" describes the strength of the classification, not an outcome.** A
  floor at RED means the action can never score below RED. If a deployment maps RED
  to something other than `BLOCK`, the floor still did its whole job.
- **A floor can only raise.** Nothing at runtime lowers one, and a floor rule cannot
  cancel another rule: there is no exemption primitive. A conditional floor that names
  no tool therefore fires on every verb carrying the fields it tests, so scope each one
  to the tools it is meant to govern.

The exported symbol names (`FloorRule`, `first_red_line_hit`, `match_red_line`)
keep both vocabularies for compatibility and are not changing.

---

## What this replaces

- **GO / ASK / STOP** — never a fivedrisk verdict set. If you see it in a docstring
  or example, it is stale (the LangGraph node emits band names, lowercased, as its
  edge keys — see `langgraph_node.route_by_band`).
- **A "3-verdict" gate** — the 3-band *experience* (YELLOW folded into GREEN when
  `enable_yellow_band` is off) is a band-display choice, not a separate verdict model.
- **ALLOW / LOG_ELEVATED / ESCALATE / BLOCK pitch set** — map onto the disposition
  ladder above; the canonical names are the ladder's.

## Patent boundary

This taxonomy describes **bands and dispositions only**. It deliberately says
nothing about coupling severity to token cost — fivedrisk OSS keeps cost *control*
(budget accumulation) strictly separate from severity, and constructs no fused
cost×risk score.
