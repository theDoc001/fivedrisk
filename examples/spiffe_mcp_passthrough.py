"""SPIFFE workload identity → MCP-shaped agent → fivedrisk policy.

Reference example for the agent-identity passthrough pattern.

What this shows:
  1. A mock SPIRE workload API hands a SPIFFE Verifiable Identity Document
     (SVID URI) to an agent.
  2. The agent decorates every tool call with the SVID as an opaque
     identity claim via `Action.metadata["agent_identity"]`.
  3. fivedrisk scores the action, writes an audit-log entry, and the
     identity flows through unchanged so SOC/SIEM tools can correlate.

What this does NOT show:
  - Real SPIRE deployment (use Docker compose with spiffe/spire-server and
    spiffe/spire-agent images for that).
  - JWT signature verification or X.509 chain validation (post-OSS).
  - A real MCP server (use the MCP Python SDK for that).
  - Identity-aware policy rules (post-OSS).

The mocks below are intentionally simple. Replace `MockSpireWorkloadAPI`
with a real `pyspiffe` client and `MockMCPServer` with a real MCP server
to make this a live deployment.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from typing import Any, Dict

from fivedrisk import classify_tool_call, score
from fivedrisk.logger import DecisionLog
from fivedrisk.policy import Policy


# ─── Mock 1: SPIRE workload API ─────────────────────────────────

@dataclass
class MockSVID:
    """A fake SPIFFE Verifiable Identity Document.

    A real SVID would be a signed JWT or an X.509 certificate. This mock
    captures only the workload URI (the field fivedrisk's audit log cares
    about for correlation).
    """
    uri: str
    expires_at_unix: int  # would be enforced by real SPIRE; ignored here


class MockSpireWorkloadAPI:
    """Stand-in for a real SPIRE workload API client (e.g. pyspiffe).

    A real client would: connect to a SPIRE agent over a Unix domain
    socket, present the workload's selectors (process attributes), and
    receive an SVID signed by the SPIRE trust bundle. The mock returns a
    static identity for the example.
    """

    def __init__(self, workload_uri: str) -> None:
        self._uri = workload_uri

    def fetch_svid(self) -> MockSVID:
        return MockSVID(uri=self._uri, expires_at_unix=9999999999)


# ─── Mock 2: MCP-shaped agent server ────────────────────────────

class MockMCPServer:
    """Stand-in for a real MCP server that calls into fivedrisk.

    A real MCP server would: accept tool-call requests from a client,
    enforce policy via fivedrisk's hooks or @gate decorator, and return
    tool results. The mock executes the policy check inline.
    """

    def __init__(self, policy: Policy, audit_log: DecisionLog) -> None:
        self.policy = policy
        self.audit_log = audit_log

    def handle_tool_call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        agent_identity: str,
    ) -> Dict[str, Any]:
        """Score the requested tool call and record the decision."""
        action = classify_tool_call(
            tool_name=tool_name,
            tool_input=tool_input,
            policy=self.policy,
            source="mcp-server",
        )
        # Attach the identity claim as an opaque string. fivedrisk does
        # not parse it, validate it, or interpret it. It only flows it
        # through to the audit-log entry.
        action.metadata["agent_identity"] = agent_identity

        scored = score(action, self.policy)
        log_id = self.audit_log.log(scored)

        return {
            "band": str(scored.band),
            "rationale": scored.rationale,
            "audit_log_id": log_id,
            "allowed": scored.band.value not in {"ORANGE", "RED"},
        }


# ─── Walkthrough ────────────────────────────────────────────────

def main() -> None:
    # 1. Set up a fivedrisk audit log in a temp file
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    audit_log = DecisionLog(path=db_path)
    policy = Policy()

    # 2. Agent fetches its identity from SPIRE
    spire = MockSpireWorkloadAPI("spiffe://example.org/agents/triage-bot")
    svid = spire.fetch_svid()
    print(f"Agent identity (SVID URI):\n  {svid.uri}\n")

    # 3. Agent sends a tool-call request through the MCP server
    server = MockMCPServer(policy=policy, audit_log=audit_log)

    # Scenario A: a benign read
    print("=" * 60)
    print("Scenario A: Agent reads a config file")
    print("=" * 60)
    result_a = server.handle_tool_call(
        tool_name="Read",
        tool_input={"path": "/etc/agent/config.json"},
        agent_identity=svid.uri,
    )
    print(f"  Band:        {result_a['band']}")
    print(f"  Rationale:   {result_a['rationale']}")
    print(f"  Audit row:   {result_a['audit_log_id']}")

    # Scenario B: a destructive bash command
    print()
    print("=" * 60)
    print("Scenario B: Agent runs rm -rf")
    print("=" * 60)
    result_b = server.handle_tool_call(
        tool_name="Bash",
        tool_input={"command": "rm -rf /tmp/cache"},
        agent_identity=svid.uri,
    )
    print(f"  Band:        {result_b['band']}")
    print(f"  Rationale:   {result_b['rationale']}")
    print(f"  Audit row:   {result_b['audit_log_id']}")

    # 4. Inspect the audit log: identity is preserved on every row
    print()
    print("=" * 60)
    print("Audit log review")
    print("=" * 60)
    rows = audit_log.query_recent(limit=10)
    for row in rows:
        identity = "unknown"
        if row.get("metadata"):
            import json as _json
            try:
                metadata = _json.loads(row["metadata"])
                identity = metadata.get("agent_identity", "unknown")
            except (ValueError, TypeError):
                pass
        print(f"  #{row['id']:>3}  tool={row['tool_name']:<10} band={row['band']:<6} identity={identity}")

    # 5. Demonstrate SOC-style correlation query
    print()
    print("=" * 60)
    print("SOC query: every action by spiffe://example.org/agents/triage-bot")
    print("=" * 60)
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        result = conn.execute(
            """
            SELECT id, timestamp, tool_name, band, rationale
            FROM decisions
            WHERE json_extract(metadata, '$.agent_identity') = ?
            ORDER BY id
            """,
            (svid.uri,),
        ).fetchall()
        for row in result:
            print(f"  #{row['id']:>3}  {row['timestamp'][:19]}  {row['tool_name']:<10} {row['band']}")

    # 6. Cleanup
    import os
    os.unlink(db_path)
    print()
    print("Done. To make this real:")
    print("  1. Replace MockSpireWorkloadAPI with pyspiffe (real SPIRE agent).")
    print("  2. Replace MockMCPServer with a real MCP server using mcp Python SDK.")
    print("  3. Add signature verification on the SVID before trusting it.")
    print("  4. Configure DecisionLog with a persistent path.")


if __name__ == "__main__":
    main()
