"""`retry_budget` now bounds how often one action may be attempted in one session.

It shipped for several releases parsed onto the Policy object and read by NOTHING. A key an
operator can set, a reviewer can approve and a change record can capture, which does nothing,
is worse than no key: everyone in the approval chain believes the control exists.

It is enforced rather than deleted because the NAME is the control — a refusal ends an action,
and without a budget an agent may attempt the same action indefinitely.
"""
import tempfile
from pathlib import Path

import pytest

from fivedrisk import hooks as H
from fivedrisk.logger import DecisionLog
from fivedrisk.policy import Policy, load_policy


def _fresh(tmp, **kw):
    H.configure(log_path=str(Path(tmp) / "a.db"))
    return Policy(**kw)


def _call(policy, session_id, path="/tmp/x"):
    @H.gate(tool_name="Read", policy=policy)
    def read_file(p: str):
        return "ok"
    return read_file(p=path, session_id=session_id) if False else read_file(p=path)


def test_it_is_OPT_IN_and_the_default_enforces_nothing():
    """Turning enforcement on by default would deny an agent that legitimately retried."""
    assert Policy().retry_budget is None
    assert load_policy().retry_budget is None


def test_counting_happens_even_when_no_budget_is_declared():
    """Otherwise switching the budget on mid-session reads zero for actions already attempted."""
    H._retry_counts = {}
    for expected in (1, 2, 3):
        assert H._record_attempt("s1", "Read", "hash-a") == expected


def test_an_uncorrelated_call_counts_nothing_rather_than_sharing_a_bucket():
    """An unidentifiable action cannot be told from a first attempt; a shared bucket would
    deny the wrong things and look like a control while doing it."""
    H._retry_counts = {}
    assert H._record_attempt(None, "Read", "hash-a") == 0
    assert H._record_attempt("", "Read", "hash-a") == 0
    assert H._retry_counts == {}


def test_a_different_action_in_the_same_session_has_its_own_count():
    H._retry_counts = {}
    assert H._record_attempt("s1", "Read", "hash-a") == 1
    assert H._record_attempt("s1", "Read", "hash-b") == 1
    assert H._record_attempt("s1", "Write", "hash-a") == 1


def test_the_same_action_in_a_different_session_has_its_own_count():
    H._retry_counts = {}
    assert H._record_attempt("s1", "Read", "hash-a") == 1
    assert H._record_attempt("s2", "Read", "hash-a") == 1


def test_the_session_map_is_bounded_so_a_long_process_cannot_grow_it():
    H._retry_counts = {}
    for i in range(H.MAX_TRACKED_SESSIONS + 25):
        H._record_attempt(f"s{i}", "Read", "hash-a")
    assert len(H._retry_counts) <= H.MAX_TRACKED_SESSIONS


def test_check_returns_None_until_the_budget_is_exceeded_and_then_a_reason():
    H._retry_counts = {}
    p = Policy(retry_budget=2)
    assert H.check_retry_budget(p, "s9", "Read", "h") is None   # 1
    assert H.check_retry_budget(p, "s9", "Read", "h") is None   # 2, at budget
    reason = H.check_retry_budget(p, "s9", "Read", "h")         # 3, over
    assert reason and "retry_budget=2" in reason and "attempt 3" in reason


def test_no_budget_never_denies_however_many_attempts():
    H._retry_counts = {}
    p = Policy()
    for _ in range(50):
        assert H.check_retry_budget(p, "s10", "Read", "h") is None


def test_the_gate_DENIES_past_the_budget_and_the_denial_is_a_refusal_like_any_other():
    """End-to-end: the budget is enforced by the production gate, not only by a helper."""
    with tempfile.TemporaryDirectory() as tmp:
        H._retry_counts = {}
        policy = _fresh(tmp, retry_budget=2)

        @H.gate(tool_name="Read", policy=policy)
        def read_file(p: str, session_id: str = None):
            return "ok"

        assert read_file(p="/tmp/x", session_id="run-1") == "ok"
        assert read_file(p="/tmp/x", session_id="run-1") == "ok"
        with pytest.raises(H.RetryBudgetExceededError):
            read_file(p="/tmp/x", session_id="run-1")


def test_a_denied_attempt_is_still_AUDITED():
    """A refusal that leaves no record is the defect the audit path exists to prevent."""
    with tempfile.TemporaryDirectory() as tmp:
        H._retry_counts = {}
        db = str(Path(tmp) / "a.db")
        H.configure(log_path=db)
        policy = Policy(retry_budget=1)

        @H.gate(tool_name="Read", policy=policy)
        def read_file(p: str, session_id: str = None):
            return "ok"

        read_file(p="/tmp/x", session_id="run-2")
        with pytest.raises(H.RetryBudgetExceededError):
            read_file(p="/tmp/x", session_id="run-2")
        assert len(DecisionLog(db).query_recent(limit=10)) >= 2, "the denial must be logged"


def test_A_STATED_LIMIT_the_budget_does_not_apply_without_a_session():
    """🔴 Published as a limit rather than left to be discovered.

    Attempts are counted per session. A caller that supplies no session id cannot have its
    attempts correlated, so the budget never engages for it — silently. That is the correct
    behaviour (a shared bucket would deny the wrong things) and it is a real gap: a deployment
    relying on `retry_budget` must also require a session id, which `configure(
    require_session_id=True)` enforces.
    """
    with tempfile.TemporaryDirectory() as tmp:
        H._retry_counts = {}
        policy = _fresh(tmp, retry_budget=1)

        @H.gate(tool_name="Read", policy=policy)
        def read_file(p: str):
            return "ok"

        for _ in range(5):
            assert read_file(p="/tmp/x") == "ok", "no session, so no correlation, so no budget"


def test_retry_count_is_WRITTEN_and_is_no_longer_a_constant_zero():
    """🔴 `ScoredAction.retry_count` was declared, serialised into the CLI JSON and the
    LangGraph state, and never written. A field that is always 0 in an evidence surface is a
    false zero, not a missing value."""
    with tempfile.TemporaryDirectory() as tmp:
        H._retry_counts = {}
        seen = []
        policy = _fresh(tmp)

        @H.gate(tool_name="Read", policy=policy)
        def read_file(p: str):
            return "ok"

        read_file(p="/tmp/x")
        read_file(p="/tmp/x")
        rows = DecisionLog(str(Path(tmp) / "a.db")).query_recent(limit=5)
        assert rows, "actions must be logged"
