# Security policy

fivedrisk is a deterministic policy gate. Code that runs in front of an agent's tool calls
is worth reporting bugs in, so this file says how.

## Supported versions

| Version | Supported |
|---|---|
| 0.7.x | Yes |
| 0.6.x and earlier | No. See the advisory below. |

Fixes land on the latest minor version. There is no backport branch.

### Advisory affecting 0.6.0 and earlier

**0.6.0 and every earlier release carry two floor fail-opens.** Both are fixed in 0.7.0 and
both are described in full at the top of [CHANGELOG.md](CHANGELOG.md).

* **SEC-1, the checksum axis could read across a field boundary.** Candidate extraction
  joined the whole tool input into one string, so a genuine identifier could fail to be
  extracted at all when a neighbouring field merged with it. Measured against the published
  0.6.0 wheel downloaded from PyPI: with a Luhn-valid test card number present and a
  `checksum: luhn` floor declared, 17 of 26 combinations of a neighbouring field's rendering
  and position failed to fire (65.4%, Wilson 95% interval 46.2% to 80.6%). On 0.7.0, 0 of the
  same 26 fail. Whether it fired could not be predicted from the field name, so if you
  declared a `checksum` floor on 0.6.0 or earlier, assume it did not fire reliably.
* **SEC-2, `first_red_line_hit` returned the first firing rule rather than the strictest.**
  A soft floor listed earlier could swallow a hard red line firing on the same action, so
  list position decided a verdict.

Neither needs a configuration change to be exposed. If you use `checksum` floor axes, or a
rule set that mixes floor bands, upgrade.

## Reporting a vulnerability

Open a [GitHub security advisory](https://github.com/theDoc001/fivedrisk/security/advisories/new)
on this repository. That keeps the report private until there is something to say publicly.

If you would rather not use GitHub, open a normal issue saying only that you have a security
report and how to reach you. Do not put the detail in a public issue.

Useful in a report, in rough order of usefulness:

1. the version, from `pip show fivedrisk`
2. the smallest policy and tool input that reproduces it
3. what you expected the verdict to be and what it was
4. whether the failure is fail-open (something passed that should have been floored) or
   fail-closed (something blocked that should not have been)

Fail-open findings are the ones worth waking up for.

## What to expect, as a target rather than a promise

This is a personal open-source project, maintained in personal time. These are what I aim
for, not guarantees, and I would rather state them honestly than publish a number I cannot
keep:

* an acknowledgement within about **five working days**
* an assessment of whether it reproduces, and a severity, within about **two weeks**
* a fix released when one is ready, with the advisory naming the affected versions

If you have not heard back in two weeks, assume the message was missed rather than ignored,
and ping the thread.

## Disclosure posture

Coordinated. Report privately, and I will work the fix with you and credit you in the
release notes unless you would rather not be named. Once a fix is released, the advisory
states the affected versions, the exposure condition and the remedy, in the same terms as
the SEC-1 and SEC-2 entries above.

Ninety days is a reasonable ceiling on how long a report should stay private. If a fix is
taking longer than that, publish. An unfixed defect that users do not know about is worse
than one they can work around.

## Scope

In scope: anything that makes the gate reach the wrong verdict, especially in the fail-open
direction, and anything in this repository that mishandles the data it is given.

Out of scope, because fivedrisk does not claim them:

* **It is not an authenticity mechanism.** The audit-log hash chain is tamper evidence over
  a local file, and `Policy.content_hash()` is a content digest, not a signature. Anything
  that can write the database can rewrite it. See [docs/audit-trail.md](docs/audit-trail.md).
* **It is not a semantic guardrail.** It assesses whether an action is dangerous, out of
  policy or out of pattern, never whether an agent's decision was correct. See
  [docs/spec/scope.md](docs/spec/scope.md).
* A regex-based detector missing a phrasing is a corpus gap, which is worth an ordinary
  issue rather than a security report, unless it defeats a floor rule you had declared.
