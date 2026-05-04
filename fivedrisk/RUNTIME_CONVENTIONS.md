# 5D Runtime Conventions

This document defines the runtime identity and enforcement conventions used by
5D's active integrations.

## Session identity

When runtime drift tracking is enabled, integrations should provide a stable
session identifier using the first available key from:

- `session_id`
- `thread_id`
- `conversation_id`
- `run_id`

If `require_session_id=True` is passed to `fivedrisk.hooks.configure()`, missing
session identity becomes a blocking error for runtime integrations.

## Destination policy

5D can optionally enforce outbound destination controls in `fivedrisk.hooks`
using:

- `destination_allowlist`
- `destination_denylist`
- `enforce_destination_policy`

When allowlist mode is enabled:

- denylisted destinations are always blocked
- non-allowlisted destinations are blocked if `enforce_destination_policy=True`
- otherwise they are logged as rationale warnings

## Detector corpus

The prompt-injection and egress detectors are versioned in
[detectors.py](detectors.py).

Current detector corpus version:

- `2026-04-14.2`
