# fivedrisk configuration and recovery reference

Read this reference when selecting a policy, setting audit paths, diagnosing a setup,
or rolling back a partial installation. Adapter-specific wiring remains in
[`adapters.md`](adapters.md).

## Configuration ownership

Separate facts the deployer owns from invariants the library owns.

The deployer owns the names and semantics of its tools, its real destinations, its
autonomy level, its approval workflow, its spend envelope, and its audit-log location.
Those values must come from the deployment rather than being guessed by the setup agent.

`deployment-profile.yaml` is the operator-reviewed design and acceptance record. The
runtime does not load it. A runtime `policy.yaml` is a separate, narrower artifact that
contains only controls supported by the installed fivedrisk version. Preserve both: the
profile records unresolved requirements and exact acceptance cases that cannot be safely
compiled into runtime policy.

The library owns the band vocabulary, policy parsing, fail-closed behavior, and adapter
contracts. Do not redefine those in a copied wrapper. Use the shipped adapter and policy
loader so one implementation decides each invariant.

## Safe starting procedure

1. Confirm the deployment profile and every item previously labelled `inferred` or
   `unresolved`.
2. Record the active interpreter and installed fivedrisk version.
3. Inventory the exact tool-execution path. A wrapper beside that path is not a gate.
4. List actions that must execute, require approval, and be blocked. Use simulated calls;
   never probe with a live destructive action.
5. Inspect the shipped presets. Copy the closest match to an operator-owned path, or use
   shipped defaults when no preset is a defensible match.
6. Configure an explicit durable audit path. Treat a temporary fallback warning as a
   deployment finding, not a successful durable setup.
7. Validate the policy. Resolve both validation errors and warnings before activation.
8. Wire one adapter once, at the actual pre-execution boundary.

The public ChatGPT/Codex skill is advisory and does not activate host lifecycle hooks.
For the separate manual integration, use its host-specific guide and the same verified
interpreter used for installation. This release's manual launcher is Claude-specific,
not a Codex hook adapter. The public ZIP omits its configuration, launcher, and starter
policy. Manual hook packages are not eligible for the public plugin directory.

Do not silently enable a human-approval flag. If the host has no real approval channel,
ORANGE stays blocked. When the host can provide a stable session identifier, require it
so sequence tracking does not silently reset per call.

## Change discipline

- Keep the last validated policy under the user's source control or backup process.
- Change one policy concern at a time, then validate and rerun representative cases.
- Preserve audit rows across a policy change; they are evidence of which policy behavior
  was active, not disposable setup output.
- A policy that parses but produces surprising results is not fixed by relaxing every
  threshold. Inspect the per-dimension rationale and the first firing floor rule.
- Re-run the real adapter path after any package, framework, hook, policy, or interpreter
  change. An import-only check cannot prove the gate still sits before execution.

## Recovery matrix

| Failure | Contain | Recover | Reverify |
|---|---|---|---|
| Package missing from the agent process | keep the new hook disabled | select the agent's interpreter and install there | import, CLI help, version |
| Policy invalid | do not activate it | restore the last validated operator-owned policy or correct the reported errors | policy validator, smoke check |
| All actions unexpectedly block | pause tool execution; retain the audit rows | inspect scores and firing rules; correct only the deployment fact that is wrong | allowed, approval, and denied cases |
| ORANGE executes without review | disable the affected adapter path immediately | remove the false approval-channel declaration and wire a real review path | ORANGE must block or reach an actual reviewer |
| Denied action reaches the executor | disable the affected adapter path immediately | move the shipped adapter to the real pre-execution boundary | simulated denial proves the executor was not called |
| Audit path falls back to temporary storage | do not treat the setup as durable | configure an explicit writable path without deleting the fallback evidence | write a new decision and read it from that path |
| Partial hook or adapter edit | stop new tool execution | revert only the setup-owned edit through source control or the saved copy | full verification sequence |

Recovery is complete only after the policy validates, the smoke check passes, the
simulated GREEN and RED example passes, and the actual adapter produces an allowed
decision plus a pre-execution denial in the configured audit log.

## Evidence in the repository

- `docs/quickstart.md`: install, policy selection, action inventory, and audit log.
- `docs/spec/deployment.md`: startup configuration, ORANGE handling, session identity,
  floor rules, and verification commands.
- `fivedrisk/hooks.py`: `configure()` and the process-global setup surface.
- `fivedrisk/cli.py`: policy validation and blocking exit semantics.
- `fivedrisk/logger.py`: durable log behavior and temporary fallback warning.
- `fivedrisk/tests/test_skill_setup.py`: executable setup-skill scenarios.
