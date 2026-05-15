# Decision log analysis cookbook

**Scope:** Sample SQL queries against fivedrisk's audit log (a SQLite database at the path you configured via `DecisionLog(path=...)`). These queries answer common operational and compliance questions without writing application code.

**Schema:** The `decisions` table records one row per scored action. Columns:

```
id, timestamp, tool_name, tool_input_hash,
data_sensitivity, tool_privilege, reversibility, external_impact, autonomy_context,
composite_score, max_dimension, band,
rationale, source, outcome, policy_version,
session_id, routing_model, routing_floor, metadata
```

The `metadata` column is JSON. Use `json_extract()` for keys like `agent_identity`.

---

## Daily operational queries

### What ran in the last hour?

```sql
SELECT id, timestamp, tool_name, band, rationale
FROM decisions
WHERE timestamp >= datetime('now', '-1 hour')
ORDER BY id DESC;
```

### What got blocked today?

```sql
SELECT id, timestamp, tool_name, band, rationale, source
FROM decisions
WHERE band = 'RED'
  AND timestamp >= date('now')
ORDER BY id DESC;
```

### HITL queue: what is waiting for approval?

```sql
SELECT id, timestamp, tool_name, rationale, session_id, source
FROM decisions
WHERE band = 'ORANGE'
  AND outcome IS NULL
ORDER BY id DESC;
```

### Approval rate by reviewer outcome

```sql
SELECT outcome, COUNT(*) AS count
FROM decisions
WHERE band IN ('ORANGE', 'RED')
  AND timestamp >= date('now', '-7 days')
GROUP BY outcome
ORDER BY count DESC;
```

---

## Session and drift queries

### All actions in a specific session

```sql
SELECT id, timestamp, tool_name, band, composite_score, rationale
FROM decisions
WHERE session_id = 'session-abc-123'
ORDER BY id;
```

### Sessions where drift escalation fired

Rationale strings produced by Markov drift include the substring "SafetyDrift". Query:

```sql
SELECT session_id, COUNT(*) AS drift_events,
       MIN(timestamp) AS first_drift,
       MAX(timestamp) AS last_drift
FROM decisions
WHERE rationale LIKE '%SafetyDrift%'
GROUP BY session_id
ORDER BY drift_events DESC;
```

### Long sessions ranked by escalation count

```sql
SELECT session_id,
       COUNT(*) AS total_actions,
       SUM(CASE WHEN band IN ('ORANGE', 'RED') THEN 1 ELSE 0 END) AS escalations
FROM decisions
WHERE session_id IS NOT NULL
GROUP BY session_id
HAVING total_actions > 10
ORDER BY escalations DESC;
```

---

## Compliance-shaped queries

### What did agent X do in Q3?

Requires `agent_identity` to be set in `Action.metadata`. The audit log stores `metadata` as JSON.

```sql
SELECT timestamp, tool_name, band, rationale
FROM decisions
WHERE json_extract(metadata, '$.agent_identity') = 'spiffe://example.org/agents/triage-bot'
  AND timestamp BETWEEN '2026-07-01' AND '2026-09-30'
ORDER BY timestamp;
```

### All decisions involving sensitive data (D2 or D3)

```sql
SELECT id, timestamp, tool_name, data_sensitivity, band, rationale
FROM decisions
WHERE data_sensitivity >= 2
ORDER BY id DESC;
```

### Destructive actions (high reversibility cost) per day

```sql
SELECT date(timestamp) AS day,
       COUNT(*) AS destructive_actions,
       SUM(CASE WHEN band = 'RED' THEN 1 ELSE 0 END) AS blocked,
       SUM(CASE WHEN outcome = 'approved' THEN 1 ELSE 0 END) AS approved
FROM decisions
WHERE reversibility >= 3
GROUP BY day
ORDER BY day DESC;
```

### Actions routed to premium model classes

Premium = M3 (high-stakes) or M4 (trusted control plane). Useful for cost analysis.

```sql
SELECT date(timestamp) AS day,
       routing_floor,
       COUNT(*) AS action_count
FROM decisions
WHERE routing_floor IN ('M3', 'M4')
GROUP BY day, routing_floor
ORDER BY day DESC;
```

---

## Forensic / incident-response queries

### Trace back from a specific decision

```sql
SELECT * FROM decisions WHERE id = 12345;
```

### Sessions that touched many data classes (potential exfiltration pattern)

```sql
SELECT session_id,
       COUNT(DISTINCT data_sensitivity) AS distinct_data_classes,
       MIN(timestamp) AS first_action,
       MAX(timestamp) AS last_action,
       COUNT(*) AS total_actions
FROM decisions
WHERE session_id IS NOT NULL
GROUP BY session_id
HAVING distinct_data_classes >= 3
ORDER BY distinct_data_classes DESC;
```

### Bursts of external_impact actions (potential reconnaissance)

```sql
SELECT session_id, COUNT(*) AS external_burst
FROM decisions
WHERE external_impact >= 2
  AND timestamp >= datetime('now', '-1 day')
GROUP BY session_id
HAVING external_burst >= 10
ORDER BY external_burst DESC;
```

### Decisions where injection scan fired in rationale

```sql
SELECT id, timestamp, tool_name, source, rationale
FROM decisions
WHERE rationale LIKE '%injection%' OR rationale LIKE '%[exfil%'
ORDER BY id DESC
LIMIT 50;
```

---

## Aggregate dashboards

### Daily action count by band (for a simple time-series chart)

```sql
SELECT date(timestamp) AS day, band, COUNT(*) AS count
FROM decisions
WHERE timestamp >= date('now', '-30 days')
GROUP BY day, band
ORDER BY day, band;
```

### Top tools by RED band rate

```sql
SELECT tool_name,
       COUNT(*) AS total,
       SUM(CASE WHEN band = 'RED' THEN 1 ELSE 0 END) AS red_count,
       ROUND(100.0 * SUM(CASE WHEN band = 'RED' THEN 1 ELSE 0 END) / COUNT(*), 1) AS red_pct
FROM decisions
GROUP BY tool_name
HAVING total >= 100
ORDER BY red_pct DESC;
```

### Action volume by autonomy_context

Helps you understand how many actions ran with low oversight.

```sql
SELECT autonomy_context, COUNT(*) AS count
FROM decisions
WHERE timestamp >= date('now', '-7 days')
GROUP BY autonomy_context
ORDER BY autonomy_context;
```

---

## Tips for production

- **Index hot query columns.** The schema indexes `tool_name`, `band`, `session_id`, and `timestamp`. If you query frequently on `metadata` keys, add a generated column and index it (SQLite supports `ALTER TABLE ADD COLUMN identity AS (json_extract(metadata, '$.agent_identity'))`).
- **Use WAL mode.** `PRAGMA journal_mode=WAL` removes the per-write fsync penalty. Audit-log writes drop from ~5ms to under 100µs.
- **Connect read-only for analysis.** `sqlite3.connect("file:audit.db?mode=ro", uri=True)` ensures your dashboards never accidentally mutate the audit trail.
- **Rotate logs.** SQLite handles tens of millions of rows fine, but for retention compliance, archive monthly snapshots and keep the active DB scoped.
- **Re-parse rationales sparingly.** Rationale strings carry semantic information (band reasons, drift labels) but are unstructured. For programmatic queries, prefer the typed columns; use rationale for human review.

---

## What is NOT in the audit log

- Raw tool input or LLM output content. Only hashes and metadata are stored.
- PII redaction. The leakage scanner detects PII; the audit log records the match but does not store the offending content.
- Cross-process state. The log is single-database. Multi-tenant or multi-deployment aggregation lives at a higher layer.

---

*Aligned with fivedrisk v0.4.2 schema. Queries tested against the bundled `DecisionLog`.*
