"""Per-dimension test battery for classify_tool_call.

Validates the content-heuristic classifier across all five dimensions:
D (data_sensitivity), T (tool_privilege), R (reversibility),
E (external_impact), A (autonomy_context).

Each dimension has 8-10 positive cases plus a clean negative case.
This is the credibility surface for the "true 5D classification"
README claim shipped in v0.5.0.
"""

from __future__ import annotations

import pytest

from fivedrisk.classifier import classify_tool_call
from fivedrisk.policy import Policy
from fivedrisk.schema import AutonomySignals


# Empty policy so baselines do not muddy dim-specific assertions
EMPTY_POLICY = Policy(tool_defaults={})


def _classify(text: str):
    return classify_tool_call("CustomTool", {"argument": text}, policy=EMPTY_POLICY)


# ─── D — data_sensitivity ─────────────────────────────────────

class TestDataSensitivity:
    @pytest.mark.parametrize("text", [
        "Please process this password=hunter2",
        "Update the API_KEY value in config",
        "Read the secret from environment",
        "Use this auth_key=xyz123 for authentication",
        "User SSN: 123-45-6789",
        "Process the credit card number",
        "Load credentials from ~/.aws/credentials",
        "Path to /etc/passwd",
        "Read from server.pem file",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ])
    def test_sensitive_pattern_bumps_d(self, text: str) -> None:
        action = _classify(text)
        assert action.data_sensitivity >= 1, f"D should bump for: {text}"

    def test_clean_text_does_not_bump_d(self) -> None:
        action = _classify("Process the document and return a summary")
        assert action.data_sensitivity == 0


# ─── T — tool_privilege ───────────────────────────────────────

class TestToolPrivilege:
    @pytest.mark.parametrize("text", [
        "subprocess.call(['ls', '-la'])",
        "os.system('whoami')",
        "os.chmod(path, 0o777)",
        "os.chown(file, 0, 0)",
        "Run sudo apt install",
        "iam.assume_role(role_arn='...')",
        "iam.attach_user_policy(user='admin', policy_arn='...')",
        "setfacl -m u:user:rwx /var/log",
        "kubectl apply -f deployment.yaml",
        "kubectl exec into the pod",
    ])
    def test_privilege_pattern_bumps_t(self, text: str) -> None:
        action = _classify(text)
        assert action.tool_privilege >= 1, f"T should bump for: {text}"

    def test_clean_text_does_not_bump_t(self) -> None:
        action = _classify("Read the configuration file")
        assert action.tool_privilege == 0


# ─── E — external_impact ──────────────────────────────────────

class TestExternalImpact:
    @pytest.mark.parametrize("text", [
        "requests.post('https://api.example.com', data=payload)",
        "httpx.put(url, json=data)",
        "aiohttp.delete(endpoint)",
        "boto3.client('s3').upload_file(...)",
        "google.cloud.storage.Client().upload(...)",
        "stripe.PaymentIntent.create(amount=1000)",
        "Send via slack webhook",
        "Email via sendgrid",
        "Publish to discord channel",
        "Deploy the release to production",
    ])
    def test_external_pattern_bumps_e(self, text: str) -> None:
        action = _classify(text)
        assert action.external_impact >= 1, f"E should bump for: {text}"

    def test_clean_text_does_not_bump_e(self) -> None:
        action = _classify("Calculate the sum of these numbers")
        assert action.external_impact == 0


# ─── R — reversibility ────────────────────────────────────────

class TestReversibility:
    @pytest.mark.parametrize("text", [
        "Delete all the temp files",
        "DROP TABLE users",
        "Truncate the audit log",
        "Purge the cache",
        "shutil.rmtree('/tmp/build')",
        "os.unlink(filepath)",
        "git push --force origin main",
        "Use force_push to overwrite",
        "open('output.txt', 'w')",
        "Transfer funds to recipient",
        "Process the payment via stripe",
    ])
    def test_irreversible_pattern_bumps_r(self, text: str) -> None:
        action = _classify(text)
        assert action.reversibility >= 1, f"R should bump for: {text}"

    def test_clean_text_does_not_bump_r(self) -> None:
        action = _classify("Read the configuration file")
        assert action.reversibility == 0


# ─── A — autonomy_context ─────────────────────────────────────

class TestAutonomyContext:
    """A is unique: derived from AutonomySignals or set explicitly."""

    def test_default_is_zero(self) -> None:
        """No explicit int, no signals → autonomy_context=0."""
        action = classify_tool_call("Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY)
        assert action.autonomy_context == 0

    def test_explicit_int_passthrough(self) -> None:
        """Caller passing int directly is honored (override path)."""
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_context=3
        )
        assert action.autonomy_context == 3

    def test_signals_seconds_since_user(self) -> None:
        """5+ minutes since last user message bumps +1."""
        signals = AutonomySignals(seconds_since_user_message=400)
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        assert action.autonomy_context == 1

    def test_signals_retry_count(self) -> None:
        """High retry count bumps +1."""
        signals = AutonomySignals(retry_count=5)
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        assert action.autonomy_context == 1

    def test_signals_plan_depth(self) -> None:
        """Deep plan chain bumps +1."""
        signals = AutonomySignals(plan_depth=4)
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        assert action.autonomy_context == 1

    def test_signals_unattended_strong_signal(self) -> None:
        """Explicit unattended flag bumps +2 (strongest single signal)."""
        signals = AutonomySignals(unattended=True)
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        assert action.autonomy_context == 2

    def test_signals_compound(self) -> None:
        """Multiple signals compound up to cap."""
        signals = AutonomySignals(unattended=True, retry_count=5, plan_depth=4)
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        # unattended (+2) + retry (+1) + plan (+1) = 4
        assert action.autonomy_context == 4

    def test_signals_prior_hitl_clamps_at_two(self) -> None:
        """prior_hitl_approved clamps the derived autonomy at 2."""
        signals = AutonomySignals(
            unattended=True, retry_count=5, plan_depth=4, prior_hitl_approved=True
        )
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        assert action.autonomy_context == 2

    def test_explicit_int_wins_over_signals(self) -> None:
        """When both are provided, the explicit int wins."""
        signals = AutonomySignals(unattended=True)
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY,
            autonomy_context=0, autonomy_signals=signals,
        )
        assert action.autonomy_context == 0  # explicit override wins

    def test_short_session_no_bumps(self) -> None:
        """Recent activity, no retries, shallow plan → 0."""
        signals = AutonomySignals(
            seconds_since_user_message=10, retry_count=1, plan_depth=1
        )
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        assert action.autonomy_context == 0

    def test_signals_capped_at_four(self) -> None:
        """Derived value cannot exceed 4 even under extreme signals."""
        signals = AutonomySignals(
            unattended=True,
            retry_count=99,
            plan_depth=99,
            seconds_since_user_message=99999,
        )
        action = classify_tool_call(
            "Read", {"path": "/tmp/x"}, policy=EMPTY_POLICY, autonomy_signals=signals
        )
        assert action.autonomy_context <= 4
