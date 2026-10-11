#!/usr/bin/env bash
# verify-install.sh: post-install smoke check for the fivedrisk setup skill.
#
# Checks:
#   1. the explicitly selected interpreter is on PATH
#   2. metadata/spec provenance resolves to a regular installed distribution
#      without executing package code
#   3. the CLI responds through the selected interpreter in isolated mode
#   4. (optional) a policy file at $FIVEDRISK_POLICY_PATH exists and is readable
#
# Exits 0 on success, non-zero on the first hard failure.

set -u

: "${PYTHON_BIN:?Set PYTHON_BIN to the selected project interpreter}"

EXIT_CODE=0
fail() { printf 'FAIL: %s\n' "$1" >&2; EXIT_CODE=1; }
pass() { printf 'PASS: %s\n' "$1"; }

verify_provenance() {
    local output
    if output=$("$PYTHON_BIN" -I - <<'PY' 2>&1
import importlib.machinery
import importlib.metadata as metadata
import json
import re
import site
import sysconfig
from pathlib import Path

try:
    distribution = metadata.distribution("fivedrisk")
except metadata.PackageNotFoundError:
    raise SystemExit("distribution metadata missing for fivedrisk")

distribution_version = distribution.version
version_match = re.fullmatch(r"0\.7\.(\d+)", distribution_version)
if version_match is None or int(version_match.group(1)) < 1:
    raise SystemExit(
        "unsupported fivedrisk version "
        f"{distribution_version!r}; install a stable version >=0.7.1,<0.8.0"
    )

files = distribution.files
if files is None:
    raise SystemExit("distribution metadata has no recorded files")
recorded = next(
    (item for item in files if str(item).replace("\\", "/") == "fivedrisk/__init__.py"),
    None,
)
if recorded is None:
    raise SystemExit("distribution metadata does not record fivedrisk/__init__.py")

expected = Path(distribution.locate_file(recorded)).resolve(strict=True)

direct_url = distribution.read_text("direct_url.json")
if direct_url is not None:
    try:
        direct = json.loads(direct_url)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"distribution direct_url.json is malformed: {exc}")
    if direct.get("dir_info", {}).get("editable") is True:
        raise SystemExit("editable distribution is not installation proof")

install_roots = {
    Path(path).resolve()
    for path in (
        *site.getsitepackages(),
        site.getusersitepackages(),
        sysconfig.get_paths().get("purelib"),
        sysconfig.get_paths().get("platlib"),
    )
    if path
}
if not any(expected.is_relative_to(root) for root in install_roots):
    raise SystemExit(
        f"distribution provenance mismatch: {expected} is outside interpreter package directories"
    )

spec = importlib.machinery.PathFinder.find_spec(
    "fivedrisk", [str(expected.parent.parent)]
)
if spec is None or spec.origin is None:
    raise SystemExit("distribution provenance mismatch: installed fivedrisk module not found")
actual = Path(spec.origin).resolve(strict=True)
if actual != expected:
    raise SystemExit(
        f"distribution provenance mismatch: resolved {actual}, recorded {expected}"
    )

print(f"supported stable {distribution_version}; regular distribution provenance ({expected})")
PY
    ); then
        pass "$output"
    else
        fail "$output"
        return 1
    fi
}

validate_policy() {
    local label="$1"
    shift
    local output
    if output=$("$PYTHON_BIN" -I -m fivedrisk._bootstrap validate "$@" 2>&1); then
        printf '%s\n' "$output"
        case "$output" in
            *"! warning:"*)
                fail "$label validation produced warnings; verification incomplete"
                ;;
            *)
                pass "$label validates"
                ;;
        esac
    else
        printf '%s\n' "$output" >&2
        fail "$label validation failed"
    fi
}

# 1. selected Python on PATH
if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    pass "selected Python on PATH ($(command -v "$PYTHON_BIN"))"
else
    fail "selected Python not on PATH ($PYTHON_BIN)"; exit "$EXIT_CODE"
fi

# 2. metadata/spec provenance before any package execution
verify_provenance || exit "$EXIT_CODE"

# 3. package code executes only after provenance succeeds, always in isolated mode
if "$PYTHON_BIN" -I -m fivedrisk._bootstrap --help >/dev/null 2>&1; then
    pass "fivedrisk CLI responds ($PYTHON_BIN -I -m fivedrisk._bootstrap --help)"
else
    fail "fivedrisk CLI did not respond"
fi

# 4. policy validation. With no explicit path, validate the built-in policy that
# the runtime will actually use.
# Pure-shell path check; the CLI receives the path as an argument, never interpolated
# into executable Python.
if [ -n "${FIVEDRISK_POLICY_PATH:-}" ]; then
    if [ -f "$FIVEDRISK_POLICY_PATH" ] && [ -r "$FIVEDRISK_POLICY_PATH" ]; then
        pass "policy file present and readable ($FIVEDRISK_POLICY_PATH)"
        validate_policy "policy" "$FIVEDRISK_POLICY_PATH"
    else
        fail "FIVEDRISK_POLICY_PATH set but file missing/unreadable ($FIVEDRISK_POLICY_PATH)"
    fi
else
    validate_policy "built-in policy"
fi

if [ "$EXIT_CODE" -eq 0 ]; then
    printf '\nAll required checks passed.\n'
else
    printf '\nOne or more checks failed. See output above.\n' >&2
fi
exit "$EXIT_CODE"
