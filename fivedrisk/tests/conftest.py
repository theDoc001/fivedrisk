"""Shared test fixtures.

Test isolation for the hooks module's process-global config flags. `configure()`
mutates module-level state (`_require_session_id`, the destination allow/deny
lists, etc.), and a test that flips one of these leaks it into every subsequent
test unless that test happens to call `configure()` again. That made the suite
order-dependent (e.g. a `require_session_id=True` test could silently break a
later test that asserts the unconfigured logging path). This autouse fixture
restores the scalar config flags to their documented module defaults after every
test, so ordering can no longer couple tests together.

Scoped deliberately narrow: only the config flags `configure()` sets are reset.
Per-session accumulators/trackers and the log objects are left alone (tests that
need those manage them explicitly, e.g. via monkeypatch).
"""
from __future__ import annotations

import pytest

from fivedrisk import hooks


@pytest.fixture(autouse=True)
def _reset_hooks_config_flags():
    yield
    hooks._require_session_id = False
    hooks._destination_allowlist = None
    hooks._destination_denylist = frozenset()
    hooks._semantic_review_patterns = ()
