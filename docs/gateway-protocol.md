# JSON-lines gateway protocol 1

The gateway is a long-lived subprocess for non-Python hosts. Start it with an explicit
policy and absolute audit path:

```bash
"$PYTHON_BIN" -I -m fivedrisk._bootstrap --policy policy.yaml \
  --log-path /absolute/path/fivedrisk-decisions.db gateway stdio
```

Standard output is protocol data only. Read and validate the first line before sending
actions:

```json
{"ready":true,"protocol_version":1,"engine":"fivedrisk","engine_version":"0.7.1"}
```

Reject the process unless `ready` is exactly `true`, `protocol_version` is `1`, `engine`
is `fivedrisk`, and the engine version is supported by the caller.

Each later input line is one JSON object. Supply a unique `id` for correlation:

```json
{"id":"call-17","tool_name":"Bash","params":{"command":"pwd"},"session_id":"session-3","autonomy":1}
```

`tool_name` must be a non-empty string. `params` must be a JSON object. `session_id` and
the optional trace fields (`agent_id`, `run_id`, `trace_id`, `span_id`,
`parent_span_id`) must be strings. `autonomy` must be an integer from 0 through 4.

A scored response echoes `id` and includes `band`, `scores`, `composite_score`,
`rationale`, `audit_log_id`, and `policy_version`. A pre-score input block uses band
`RED`, `blocked: true`, and `block_reason`. An invalid request returns `error` and
`error_type`; it is a block, never permission to execute. In particular,
`UnsupportedPolicyControls` means the selected policy requests admission controls that
protocol 1 cannot enforce.

The caller may execute only exact `GREEN` or `YELLOW`. Exact `ORANGE` means hold for a
real human approval flow; this protocol does not consume approval. Exact `RED`, an
unknown/missing band, an error frame, malformed JSON, a duplicate or mismatched `id`,
timeout, EOF, broken pipe, process exit, or handshake failure must block. Never infer a
decision from line order when `id` is present.

Protocol 1 provides deterministic classification, input injection and configured
semantic-review scans, scoring, optional session drift, routing metadata, and the
selected SQLite audit log. Policies enabling `identity_required`, retry budgets, or
token-budget admission are rejected fail closed on this surface because protocol 1 has
no fields or lifecycle for enforcing those controls. Destination allow/deny configured
through Python `configure()` is also outside this subprocess contract.

Keep one process alive for multiple calls. Do not start a fresh interpreter per action.
Treat standard error as diagnostics only, never as a decision channel.
