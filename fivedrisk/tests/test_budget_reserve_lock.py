"""S3 concurrency guard: reserve_for_tool_call must not race past the cap.

Reproduces the check-then-act TOCTOU class (OSS audit M1): many threads
reserving at once must never over-commit the session budget beyond the cap.
"""

from __future__ import annotations

import threading

from fivedrisk.budget_accumulator import BudgetAccumulator


def test_concurrent_reservations_never_exceed_cap() -> None:
    # Cap allows exactly 10 reservations of 1000 tokens; 50 threads race.
    acc = BudgetAccumulator(session_id="race", max_session_budget_tokens=10_000)
    n_threads = 50
    approved_ids: list[str] = []
    approved_lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker(i: int) -> None:
        barrier.wait()  # maximize contention on the check-then-act
        r = acc.reserve_for_tool_call(f"call-{i}", worst_case_tokens=1000)
        if r.approved:
            with approved_lock:
                approved_ids.append(f"call-{i}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Invariant: pending reservations never exceed the cap.
    pending = sum(r.worst_case_tokens for r in acc.reservations_pending.values())
    assert pending <= 10_000
    assert len(approved_ids) == 10  # exactly cap/size approvals, no over-grant


def test_lock_not_in_equality_or_repr() -> None:
    # The lock field must not break value semantics of the dataclass.
    a = BudgetAccumulator(session_id="s", max_session_budget_tokens=100)
    b = BudgetAccumulator(session_id="s", max_session_budget_tokens=100)
    assert a == b
    assert "_lock" not in repr(a)
