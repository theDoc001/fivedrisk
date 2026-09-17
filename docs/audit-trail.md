# The audit trail: what a decision record can answer

Every decision fivedrisk makes can be appended to a SQLite log. Since 0.7.0 that log
answers three questions it could not answer before: **who authorised this**, **which policy
content decided it**, and **has any row changed since it was written**.

This page is the documentation for those columns and for `verify_chain()`. The CHANGELOG
records that they arrived; a changelog is a record of change, not documentation of state,
and a reader arriving at 0.7.0 has no reason to read the 0.6.x entries.

## The six columns

`DecisionLog` adds six nullable columns to the `decisions` table. All six are additive, and
old rows are never back-filled.

| Column | Answers |
|---|---|
| `acting_principal_id` | Which principal the action was taken on behalf of |
| `acting_principal_type` | What kind of principal that is (`service`, `user`, and so on) |
| `outcome_history` | The full ordered sequence of outcomes, not only the latest one |
| `config_hash` | Which policy CONTENT decided, independent of a hand-typed version string |
| `prev_hash` | The previous row's `record_hash`, which is what links the chain |
| `record_hash` | A digest over this row's decision-time fields |

`outcome` still holds the latest value and is still overwritten, so existing queries are
unaffected. `outcome_history` accumulates alongside it, because a decision that went
`pending` then `approved` then `executed` previously left no trace of having been anything
but its last state, and "what happened, in what order" is the question an audit log exists
to answer.

## Why `config_hash` rather than a version string

`Policy.version` is a string the author types. Two deployments can both say `0.2.0` with
different thresholds, weights and floor rules, and a record carrying only the version cannot
tell them apart. Nor can it show that the policy changed under a version that stayed the
same, which is the case that matters when somebody asks why an action scored differently
last month.

`Policy.content_hash()` covers every field that can change a verdict: thresholds, weights,
tool defaults, bash overrides, destination and admission settings, and the compiled floor
rules.

## Try it

```python
import json, sqlite3
from fivedrisk.logger import DecisionLog
from fivedrisk.policy import load_policy
from fivedrisk.schema import Action, ActingIdentity
from fivedrisk.scorer import score

log = DecisionLog("decisions.db")
policy = load_policy("read_only")

action = Action(
    tool_name="Bash",
    tool_input={"command": "rm -rf /var/lib/data"},
    data_sensitivity=2, tool_privilege=4, reversibility=4,
    acting_identity=ActingIdentity(principal_id="svc-etl@example",
                                   principal_type="service"),
)
row_id = log.log(score(action, policy), config_hash=policy.content_hash())

log.update_outcome(row_id, "pending")
log.update_outcome(row_id, "approved")
log.update_outcome(row_id, "executed")

print(json.dumps(log.verify_chain(), indent=2))
```

Real output, three rows logged against the `read_only` preset, hashes truncated to ten
characters for width:

```
>>> pol.content_hash()
2386a9b82f70407b

>>> log.verify_chain()          # untouched log, after three outcome updates
{
  "ok": true,
  "checked": 3,
  "skipped_pre_chain": 0,
  "first_bad_id": null,
  "reason": null
}

>>> the six columns as stored
{"id": 1, "acting_principal_id": "svc-etl@example", "acting_principal_type": "service", "outcome_history": null, "config_hash": "2386a9b82f", "prev_hash": null, "record_hash": "ebe7675ed9"}
{"id": 2, "acting_principal_id": "svc-etl@example", "acting_principal_type": "service", "outcome_history": "[\"pending\", \"approved\", \"executed\"]", "config_hash": "2386a9b82f", "prev_hash": "ebe7675ed9", "record_hash": "97ed5843a3"}
{"id": 3, "acting_principal_id": "svc-etl@example", "acting_principal_type": "service", "outcome_history": null, "config_hash": "2386a9b82f", "prev_hash": "97ed5843a3", "record_hash": "4f461d3111"}
```

Note row 1: `prev_hash` is `null` because it starts the chain, and each later row's
`prev_hash` is the row above it's `record_hash`. Note row 2: three outcome updates
accumulated in `outcome_history`, and `record_hash` did not change, which is the next
section.

## What an edited row looks like

```
>>> edit one row in place, the way an after-the-fact change looks
    UPDATE decisions SET band='GREEN' WHERE id=2;

>>> log.verify_chain()          # after the edit
{
  "ok": false,
  "checked": 1,
  "skipped_pre_chain": 0,
  "first_bad_id": 2,
  "reason": "record_hash does not recompute, this row or an earlier one was changed after it was written"
}
```

`checked` is 1, not 0: row 1 verified, and the walk stopped at the first row that did not.
`first_bad_id` names it.

## What a pass does NOT mean

An integrity check that gets over-read is worse than none, so this is stated plainly.

* **It is evidence, not proof.** The database is a local file. Anything that can write it
  can rewrite the whole tail and produce a consistent chain. This detects edits. It does not
  stop an adversary who has write access and patience.
* **`content_hash()` is a digest, not a signature.** It proves two policies are the same
  policy. It does not prove who wrote either of them.
* **`outcome` and `outcome_history` are deliberately outside the chain.** They are mutable
  by design. `update_outcome()` does not recompute `record_hash`, because silently re-hashing
  on every outcome update would let any later edit repair its own evidence, which is the
  opposite of tamper evidence. An outcome recorded after the fact is a new fact about an old
  row, not a correction to it.
* **Rows predating the chain are skipped, never passed.** They are counted separately in
  `skipped_pre_chain`. An unverifiable row must not read as a verified one.

## Upgrading a log written before 0.7.0

The columns are added by `ALTER TABLE` on open, so an existing log keeps working. Rows
written earlier hold NULL in all six, and `DecisionLog.MIGRATION_NOTE` states what that
means:

> Rows written before 0.7.0 have NULL in `acting_principal_id`, `acting_principal_type`,
> `config_hash`, `outcome_history`, `prev_hash` and `record_hash`. NULL here means THE
> COLUMN DID NOT EXIST, never "there was no identity", "no policy applied" or "the chain is
> intact". These cannot be back-filled: the identity and the policy content are not
> recoverable from the stored row, and a hash chain computed now over rows written earlier
> would attest to nothing. Treat the first row carrying a `record_hash` as the start of the
> verifiable chain.

The note is an attribute on the class rather than a line in a changelog, because the person
querying an old log is not the person who upgraded it.

## Related

* [decision-log-cookbook.md](../decision-log-cookbook.md), SQL against this table
* [spec/scope.md](spec/scope.md), what a verdict does and does not assess
