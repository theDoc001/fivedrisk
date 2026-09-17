# fivedrisk scope — what it assesses, and what it deliberately does not (canonical)

**Status:** canonical. This is the single source of truth for the *scope of the
assessment* fivedrisk performs. `taxonomy.md` owns what the verdicts mean;
`deployment.md` owns how to configure them; this file owns **what question a
fivedrisk verdict answers.** Read this before assuming fivedrisk grades something
it does not.

---

## The one question fivedrisk answers

> **"Given this deployment's policy and its established normal pattern, is this
> action safe to let run?"**

That is a **security / blast-radius** question. Every one of the five dimensions
is an axis of *how much damage this action could do and how far outside the norm
it is* — never *whether the action is the right answer*:

| Dimension | Asks | It does NOT ask |
|---|---|---|
| Data Sensitivity | How sensitive is the data touched? | Is the data correct? |
| Tool Privilege | How privileged is the tool invoked? | Is invoking it the right choice? |
| Reversibility | Can this be undone cheaply? | Should it be done? |
| External Impact | Does this reach outside the boundary? | Is the outreach well-judged? |
| Autonomy Context | How much human oversight is expected? | Did the agent reason well? |

A verdict of `RED`/`BLOCK` means *this action is dangerous or out of policy*, not
*this action is wrong*. A verdict of `GREEN`/`EXECUTE` means *this action is within
the deployment's safe, in-policy, in-pattern envelope*, not *this action is correct
or high quality*.

---

## What fivedrisk MUST catch (security anomalies + policy violations)

fivedrisk exists to catch actions that are **dangerous, out of policy, or out of
the ordinary for the deployment's established pattern.** Concretely, the classes it
is built to catch:

- **Novel destination / recipient** — sending to a counterparty, account, address,
  or endpoint the deployment has never sent to before.
- **Novel jurisdiction / context** — operating in a region, system, or context
  outside the deployment's established set.
- **Abnormal magnitude** — an amount, batch size, or scope materially larger than
  the deployment's normal for that class of action.
- **Abnormal velocity / frequency** — bursts, rapid pass-through, or fan-in/fan-out
  beyond the deployment's normal rate.
- **Novel instrument / account / tool** — first use of a capability the deployment
  has not used before.
- **Privilege / scope deviation** — an action outside the scope the agent was
  granted (e.g., an agent authorised only to triage and annotate suddenly moving
  funds, filing an external report, or changing customer state).
- **Exfiltration** — regulated or sensitive data leaving to an untrusted or
  unapproved destination.
- **Unauthorised irreversible action** — an irreversible effect (money moved, report
  filed, record destroyed) taken without the authorisation the policy requires.
- **Out-of-pattern behaviour** — the general case: an action that deviates from the
  deployment's established normal, even when each individual field looks unremarkable.

The deterministic layer catches the clear-cut, structurally visible deviations
(policy-forbidden tools, exfil destinations, unauthorised irreversible actions) and
routes the rest. A secondary semantic reviewer (an "observer") catches the subtler
out-of-pattern deviations that need reading the action in context — **still a
security judgment, not a quality judgment.**

---

## What fivedrisk MUST NOT do (it is not a quality or correctness judge)

fivedrisk does **not** evaluate the semantic correctness or quality of the action's
content or the business decision behind it. That judgment belongs to the agent's own
domain model and to the human reviewer, not to the policy gate. Specifically, it
does not decide:

- Whether a financial-crime alert is a true match or a false positive **on the
  merits** (the domain model and analyst decide that; fivedrisk only asks whether
  *acting* on the disposition is in-policy and in-pattern).
- Whether a piece of code is correct, whether an answer is accurate, whether a
  summary is faithful, or whether a recommendation is good advice.
- Whether the agent reasoned well to reach its conclusion.

A gate that tries to grade correctness inevitably escalates everything (it cannot
safely clear a decision it is not equipped to judge), which destroys its value. The
discipline is strict: **fivedrisk grades the safety of the action, never the quality
of the answer.**

---

## Why the separation matters

Keeping the security question separate from the quality question is what lets the
gate do two things at once that a quality-grader cannot: **auto-clear the large
volume of safe, in-pattern, in-policy actions** (so humans are not flooded), while
**reliably catching the dangerous or anomalous minority.** Conflating the two axes
collapses the gate into either a rubber stamp or an escalate-everything bottleneck.
This is the same discipline `taxonomy.md` applies to band-vs-disposition, extended
to the assessment itself.
