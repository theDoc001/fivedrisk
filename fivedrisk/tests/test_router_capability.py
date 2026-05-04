"""Expanded router capability coverage."""

from __future__ import annotations

from fivedrisk.router import EscalationSignal, ModelConfig, ModelRouter
from fivedrisk.schema import Band, ModelClass, RoutingDecision


def _routing_decision(
    band: Band = Band.GREEN,
    floor: ModelClass = ModelClass.M1,
    selected: ModelClass = ModelClass.M1,
) -> RoutingDecision:
    return RoutingDecision(
        data_class="D1",
        risk_band=band,
        task_class="execution",
        model_floor=floor,
        selected_model=selected,
    )


class TestRouterCapability:
    def test_get_config_returns_requested_model(self):
        router = ModelRouter()
        assert router.get_config(ModelClass.M3).model_class == ModelClass.M3

    def test_route_keeps_selected_model_when_valid(self):
        router = ModelRouter()
        config = router.route(_routing_decision(selected=ModelClass.M2, floor=ModelClass.M1))
        assert config.model_class == ModelClass.M2

    def test_route_ignores_downward_escalation(self):
        router = ModelRouter()
        signal = EscalationSignal(
            from_model=ModelClass.M3,
            to_model=ModelClass.M1,
            reason="lower",
            confidence=0.1,
        )
        config = router.route(_routing_decision(selected=ModelClass.M3, floor=ModelClass.M2), signal)
        assert config.model_class == ModelClass.M3

    def test_route_honors_upward_escalation(self):
        router = ModelRouter()
        signal = EscalationSignal(
            from_model=ModelClass.M1,
            to_model=ModelClass.M3,
            reason="complex",
            confidence=0.1,
        )
        config = router.route(_routing_decision(selected=ModelClass.M1, floor=ModelClass.M1), signal)
        assert config.model_class == ModelClass.M3

    def test_route_respects_floor_above_selected(self):
        router = ModelRouter()
        config = router.route(_routing_decision(selected=ModelClass.M0, floor=ModelClass.M2))
        assert config.model_class == ModelClass.M2

    def test_route_caps_m3_to_m2_when_cloud_disabled(self):
        router = ModelRouter(cloud_enabled=False)
        config = router.route(_routing_decision(selected=ModelClass.M3, floor=ModelClass.M1))
        assert config.model_class == ModelClass.M2

    def test_route_caps_m4_to_m2_when_cloud_disabled(self):
        router = ModelRouter(cloud_enabled=False)
        config = router.route(_routing_decision(selected=ModelClass.M4, floor=ModelClass.M4))
        assert config.model_class == ModelClass.M2

    def test_model_config_is_local_for_local_only(self):
        config = ModelConfig(model_class=ModelClass.M1, local_model="qwen")
        assert config.is_local is True

    def test_model_config_is_not_local_when_cloud_present(self):
        config = ModelConfig(model_class=ModelClass.M3, local_model="qwen", cloud_model="sonnet")
        assert config.is_local is False

    def test_model_config_is_cloud_for_cloud_model(self):
        config = ModelConfig(model_class=ModelClass.M4, cloud_model="opus")
        assert config.is_cloud is True

    def test_classify_task_prompt_contains_task_text(self):
        router = ModelRouter()
        payload = router.classify_task("Review production deploy plan")
        assert "Review production deploy plan" in payload["prompt"]

    def test_classify_task_uses_phi_model(self):
        router = ModelRouter()
        payload = router.classify_task("Simple task")
        assert payload["model"] == "phi4-mini"

    def test_classify_task_requests_json_output(self):
        router = ModelRouter()
        payload = router.classify_task("Simple task")
        assert "Respond in JSON" in payload["prompt"]

    def test_advisor_tool_config_uses_ephemeral_cache(self):
        router = ModelRouter()
        config = router.build_advisor_tool_config()
        assert config["caching"]["type"] == "ephemeral"

    def test_advisor_tool_config_ttl_is_five_minutes(self):
        router = ModelRouter()
        config = router.build_advisor_tool_config()
        assert config["caching"]["ttl"] == "5m"

    def test_api_headers_expose_beta_key(self):
        router = ModelRouter()
        assert router.build_api_headers()["anthropic-beta"] == "advisor-tool-2026-03-01"

    def test_low_confidence_triggers_escalation(self):
        signal = EscalationSignal(
            from_model=ModelClass.M1,
            to_model=ModelClass.M2,
            reason="unsure",
            confidence=0.49,
        )
        assert signal.should_escalate is True

    def test_confidence_boundary_does_not_escalate_by_itself(self):
        signal = EscalationSignal(
            from_model=ModelClass.M1,
            to_model=ModelClass.M2,
            reason="steady",
            confidence=0.5,
        )
        assert signal.should_escalate is False

    def test_reasoning_depth_escalates_for_m1(self):
        signal = EscalationSignal(
            from_model=ModelClass.M1,
            to_model=ModelClass.M3,
            reason="deep reasoning",
            confidence=0.8,
            reasoning_depth=4,
        )
        assert signal.should_escalate is True

    def test_red_band_does_not_escalate_from_m4(self):
        signal = EscalationSignal(
            from_model=ModelClass.M4,
            to_model=ModelClass.M4,
            reason="already at top",
            confidence=0.9,
            five_d_band=Band.RED,
        )
        assert signal.should_escalate is False
