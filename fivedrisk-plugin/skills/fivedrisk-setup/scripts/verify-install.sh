#!/usr/bin/env bash
# verify-install.sh: post-install smoke check for the fivedrisk setup skill.
#
# Checks:
#   1. python3 is on PATH
#   2. `import fivedrisk` succeeds and prints a version
#   3. the CLI responds (`python -m fivedrisk --help`)
#   4. (optional) a policy file at $FIVEDRISK_POLICY_PATH exists and is readable
#
# Exits 0 on success, non-zero on the first hard failure.

set -u

EXIT_CODE=0
fail() { printf 'FAIL: %s\n' "$1" >&2; EXIT_CODE=1; }
pass() { printf 'PASS: %s\n' "$1"; }

# 1. python3 on PATH
if command -v python3 >/dev/null 2>&1; then
    pass "python3 on PATH ($(command -v python3))"
else
    fail "python3 not on PATH"; exit "$EXIT_CODE"
fi

# 2. import fivedrisk
if VERSION=$(python3 -c 'import fivedrisk; print(fivedrisk.__version__)' 2>&1); then
    pass "fivedrisk installed (version: $VERSION)"
else
    fail "import fivedrisk failed: $VERSION"; exit "$EXIT_CODE"
fi

# 3. CLI responds
if python3 -m fivedrisk --help >/dev/null 2>&1; then
    pass "fivedrisk CLI responds (python -m fivedrisk --help)"
else
    fail "fivedrisk CLI did not respond"
fi

# 4. policy file (optional — only checked if the operator set a path)
# Low-22 (from the claw skill): pure-shell test, never interpolate the path into python -c.
if [ -n "${FIVEDRISK_POLICY_PATH:-}" ]; then
    if [ -f "$FIVEDRISK_POLICY_PATH" ] && [ -r "$FIVEDRISK_POLICY_PATH" ]; then
        pass "policy file present and readable ($FIVEDRISK_POLICY_PATH)"
    else
        fail "FIVEDRISK_POLICY_PATH set but file missing/unreadable ($FIVEDRISK_POLICY_PATH)"
    fi
else
    printf 'SKIP: FIVEDRISK_POLICY_PATH not set; using shipped default policy.\n'
fi

if [ "$EXIT_CODE" -eq 0 ]; then
    printf '\nAll required checks passed.\n'
else
    printf '\nOne or more checks failed. See output above.\n' >&2
fi
exit "$EXIT_CODE"
