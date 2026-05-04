---
description: 5D Risk Governance Engine. Automatically scores actions on 5 risk dimensions (Data Sensitivity, Tool Privilege, Reversibility, External Impact, Autonomy Context) before execution. Use when about to perform any action that writes files, runs commands, accesses network, or touches sensitive data.
---

Before executing any tool call that could have consequences (writes, deletes, network requests, credential access), score it using the 5D Risk Governance Model:

1. Rate each dimension 0-4:
   - **Data Sensitivity**: how sensitive is the data this action reads or produces?
   - **Tool Privilege**: how privileged is the tool being invoked?
   - **Reversibility**: can this action be undone cheaply?
   - **External Impact**: does this touch anyone or anything outside the user's boundary?
   - **Autonomy Context**: how much human oversight exists right now?

2. Apply bands:
   - Any dimension ≥ 4 → **STOP** (refuse, explain why)
   - Any dimension ≥ 3 OR composite ≥ 8.0 → **ASK** (surface score to user, await approval)
   - Otherwise → **GO** (proceed, log the score)

3. Log the score to the decision log for audit and pattern learning.

When in doubt, err toward ASK over GO. Never silently proceed on a STOP action.

Composite score = sum of (dimension × weight) where weights are:
- Data Sensitivity: 1.0
- Tool Privilege: 1.2
- Reversibility: 1.5
- External Impact: 1.0
- Autonomy Context: 0.8
