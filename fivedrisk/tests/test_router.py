"""Tests for the model router and escalation logic."""

import pytest

from fivedrisk.router import ModelRouter, EscalationSignal, DEFAULT_MODEL_CONFIGS
from fivedrisk.schema import Band, ModelClass, RoutingDecision


class TestModelRouter:
    """Model routing based on 5D band + data class."""

    def test_green_d0_routes_local(self):
        router = ModelRouter()
        rd = RoutingDecision(
            data_class="D0", risk_band=Band.GREEN,
            task_class="research", model_floor=ModelClass.M0,
            selected_model=ModelClass.M1,
        )
        config = router.route(rd)
        assert config.is_local
        assert config.local_model in ("phi4-mini", "qwen3:8b")

    def test_red_routes_to_opus(self):
        router = ModelRouter()
        rd = RoutingDecision(
            data_class="D3", risk_band=Band.RED,
            task_class="execution", model_floor=ModelClass.M4,
            selected_model=ModelClass.M4,
        )
        config = router.route(rd)
        assert config.is_cloud
        assert config.cloud_model == "claude-opus-4-6"

    def test_orange_routes_to_sonnet_advisor(self):
        router = ModelRouter()
        rd = RoutingDecision(
            data_class="D2", risk_band=Band.ORANGE,
            task_class="execution", model_floor=ModelClass.M3,
            selected_model=ModelClass.M3,
        )
        config = router.route(rd)
        assert config.use_advisor is True
        assert config.cloud_advisor == "claude-opus-4-6"

    def test_cloud_disabled_caps_at_m2(self):
        router = ModelRouter(cloud_enabled=False)
        rd = RoutingDecision(
            data_class="D3", risk_band=Band.RED,
            task_class="execution", model_floor=ModelClass.M4,
            selected_model=ModelClass.M4,
        )
        config = router.route(rd)
        assert config.is_local

    def test_never_below_floor(self):
        router = ModelRouter()
        rd = RoutingDecision(
            data_class="D0", risk_band=Band.GREEN,
            task_class="research", model_floor=ModelClass.M2,
            selected_model=ModelClass.M0,  # below floor
        )
        config = router.route(rd)
        assert config.model_class.value >= "M2"


class TestEscalationSignal:
    """Capability ceiling recognition."""

    def test_low_confidence_triggers_escalation(self):
        signal = EscalationSignal(
            from_model=ModelClass.M1,
            to_model=ModelClass.M3,
            reason="Low confidence on complex planning",
            confidence=0.3,
        )
        assert signal.should_escalate is True

    def test_high_confidence_no_escalation(self):
        signal = EscalationSignal(
            from_model=ModelClass.M1,
            to_model=ModelClass.M3,
            reason="Simple task",
            confidence=0.9,
            task_complexity=1,
        )
        assert signal.should_escalate is False

    def test_high_complexity_from_m0_escalates(self):
        signal = EscalationSignal(
            from_model=ModelClass.M0,
            to_model=ModelClass.M2,
            reason="Multi-step planning",
            confidence=0.7,
            task_complexity=4,
        )
        assert signal.should_escalate is True

    def test_red_band_forces_escalation(self):
        signal = EscalationSignal(
            from_model=ModelClass.M2,
            to_model=ModelClass.M4,
            reason="Red-tier action",
            confidence=0.9,
            five_d_band=Band.RED,
        )
        assert signal.should_escalate is True

    def test_escalation_overrides_routing(self):
        router = ModelRouter()
        rd = RoutingDecision(
            data_class="D1", risk_band=Band.YELLOW,
            task_class="planning", model_floor=ModelClass.M1,
            selected_model=ModelClass.M2,
        )
        signal = EscalationSignal(
            from_model=ModelClass.M2,
            to_model=ModelClass.M3,
            reason="Complex reasoning needed",
            confidence=0.3,
        )
        config = router.route(rd, escalation=signal)
        assert config.model_class == ModelClass.M3


class TestAdvisorToolConfig:
    """Advisor Tool API compatibility."""

    def test_advisor_config_format(self):
        router = ModelRouter()
        config = router.build_advisor_tool_config()
        assert config["type"] == "advisor_20260301"
        assert config["model"] == "claude-opus-4-6"
        assert "max_uses" in config

    def test_api_headers(self):
        router = ModelRouter()
        headers = router.build_api_headers()
        assert "anthropic-beta" in headers
        assert "advisor-tool" in headers["anthropic-beta"]
