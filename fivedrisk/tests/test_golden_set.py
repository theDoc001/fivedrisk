"""Golden set integration tests — end-to-end classify + score.

Each JSON file in golden_set/ defines a tool call with an expected
band. The test loads each scenario, classifies it, scores it, and
asserts the band matches expectations.
"""

import json
from pathlib import Path

import pytest

from fivedrisk.classifier import classify_tool_call
from fivedrisk.policy import load_policy
from fivedrisk.scorer import score

GOLDEN_DIR = Path(__file__).parent / "golden_set"
POLICY_PATH = Path(__file__).parent.parent.parent / "policy.yaml"


def _load_golden_scenarios():
    """Load all golden set JSON files."""
    scenarios = []
    if not GOLDEN_DIR.exists():
        return scenarios
    for f in sorted(GOLDEN_DIR.glob("*.json")):
        with open(f) as fh:
            data = json.load(fh)
            data["_file"] = f.name
            scenarios.append(data)
    return scenarios


SCENARIOS = _load_golden_scenarios()


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[s["_file"] for s in SCENARIOS],
)
def test_golden_scenario(scenario):
    """Each golden scenario should produce the expected band."""
    policy = load_policy(POLICY_PATH) if POLICY_PATH.exists() else None

    action = classify_tool_call(
        tool_name=scenario["tool_name"],
        tool_input=scenario["tool_input"],
        policy=policy,
        autonomy_context=scenario.get("autonomy_context", 0),
        source="golden-test",
    )

    result = score(action, policy)

    expected_band = scenario["expected_band"]
    actual_band = str(result.band)

    assert actual_band == expected_band, (
        f"Scenario {scenario['_file']}: expected {expected_band}, got {actual_band}. "
        f"Composite={result.composite_score:.1f}, max_dim={result.max_dimension}, "
        f"dims={action.dimensions}. "
        f"Description: {scenario.get('description', 'N/A')}"
    )
