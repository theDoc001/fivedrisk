"""Shared test fixtures.

Test isolation for the hooks module's process-global config flags. `configure()`
mutates module-level state (`_require_session_id`, the destination allow/deny
lists, etc.), and a test that flips one of these leaks it into every subsequent
test unless that test happens to call `configure()` again. That made the suite
order-dependent (e.g. a `require_session_id=True` test could silently break a
later test that asserts the unconfigured logging path). This autouse fixture
restores the scalar config flags to their documented module defaults after every
test, so ordering can no longer couple tests together.

The suite also redirects process-global audit logging to pytest's external temp
root and disables bytecode writes.  This keeps test execution from modifying the
release candidate while preserving production defaults outside pytest.
"""
from __future__ import annotations

import os
import sys

_ORIGINAL_DONT_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True

import pytest

from fivedrisk import hooks, logger


@pytest.fixture(scope="session", autouse=True)
def _isolate_suite_outputs(tmp_path_factory):
    """Keep default audit and bytecode outputs outside the source checkout."""
    original_default_path = logger.DEFAULT_LOG_PATH
    original_log = hooks._log
    original_default_log = hooks._default_log
    had_bytecode_env = "PYTHONDONTWRITEBYTECODE" in os.environ
    original_bytecode_env = os.environ.get("PYTHONDONTWRITEBYTECODE")

    suite_dir = tmp_path_factory.mktemp("fivedrisk-suite")
    logger.DEFAULT_LOG_PATH = suite_dir / "fivedrisk_decisions.db"
    hooks._log = None
    hooks._default_log = None
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        yield
    finally:
        if had_bytecode_env:
            assert original_bytecode_env is not None
            os.environ["PYTHONDONTWRITEBYTECODE"] = original_bytecode_env
        else:
            os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
        hooks._default_log = original_default_log
        hooks._log = original_log
        logger.DEFAULT_LOG_PATH = original_default_path
        sys.dont_write_bytecode = _ORIGINAL_DONT_WRITE_BYTECODE


@pytest.fixture(autouse=True)
def _reset_hooks_config_flags():
    yield
    hooks._require_session_id = False
    hooks._destination_allowlist = None
    hooks._destination_denylist = frozenset()
    hooks._semantic_review_patterns = ()
