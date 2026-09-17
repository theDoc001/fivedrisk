# fivedrisk deployer setup guide (canonical)

**Status:** canonical. How to configure the band→disposition ladder, the session
budget cap, and the fail-closed default. Read `taxonomy.md` first for what bands
and dispositions mean, and `scope.md` for what a verdict does (and does not) assess
— 5D grades an action's security/blast-radius, never its correctness or quality.

---

## 1. Configure once at startup

```python
from fivedrisk.hooks import configure

configure(
    policy_path="policy.yaml",        # your tuned policy, or None for shipped defaults
    require_session_id=True,          # see "Fail-closed default" below
    destination_denylist=["evil.example"],
    event_path="audit.ndjson",        # optional NDJSON event stream for SIEM
)
```

`configure()` is process-global; call it before the first gated action.

## 2. The band → disposition ladder

Bands come from scoring; **dispositions are yours to set**. The default ladder
(`GREEN→EXECUTE`, `YELLOW→LOG_ELEVATED`, `ORANGE→ROUTE_HITL`, `RED→BLOCK`) is in
`taxonomy.md`. Tune YELLOW in `policy.yaml`:

```yaml
enable_yellow_band: true          # surface YELLOW as its own tier (else folded into GREEN)
yellow_model_escalation: false    # opt in to a model-class bump on YELLOW
```

- Leave `enable_yellow_band` off for a 3-band (GREEN/ORANGE/RED) experience.
- Turn it on when you want moderate-risk actions logged and dashboarded separately.

## 3. Session budget cap (cost control, not risk)

`BudgetAccumulator` enforces a per-session token ceiling with worst-case
reservation. It is deny-based cost *control* — it is NOT combined with the risk
band (no fused cost×risk score).

```yaml
# policy.yaml
max_session_budget_tokens: 100000
max_tool_call_budget_tokens: 4096
```

When a reservation would exceed the cap, `@gate` raises `BudgetExceededError` and
emits a `budget_intervention` event. See README §Cost management.

## 4. Fail-closed default (nails the ORANGE/undefined-semantics question)

fivedrisk's shipped posture is **fail-closed**:

- **`require_session_id=True`** — an action with no stable session id is **blocked**
  (not silently allowed). Leave it off only if your host cannot supply a session id
  and you accept that drift tracking is then per-call (see `taxonomy.md` / the
  `_get_drift_tracker` note in `hooks.py`).
- **ORANGE blocks pending approval.** In hosts with a native approval channel,
  ORANGE routes to HITL. In hosts without one (e.g. a CLI hook), ORANGE must map to
  a **blocking** exit (exit code 2), never a non-blocking warning — otherwise a
  "requires approval" action would run unreviewed. The shipped CLI (`python -m
  fivedrisk score`) exits 2 on both RED and ORANGE for exactly this reason.
- **Detector/observer unavailable → treat as fail-closed**, not fail-open.

## 5. Floor rules

If you author `floor:` rules, read the floor section of `taxonomy.md` first. It is canonical for
the reduction contract: the strictest firing rule wins, list position never exempts, and there is
no exemption primitive. A conditional floor that names no tool fires on every verb carrying the
fields it tests, so scope each one to the tools it is meant to govern.

## 6. Verify

```bash
python -m fivedrisk validate policy.yaml    # policy loads + ranges/regex compile
python -m fivedrisk log --recent 20         # confirm decisions are being logged
python -m fivedrisk stats                    # band breakdown
```
