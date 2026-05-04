"""5D Risk Governance Engine — Model routing and escalation.

Implements governance spec v0.3 §19 (Model Routing Policy) with
capability ceiling recognition and the Advisor Tool pattern.

Routing chain:
  phi-4-mini (M0) → task classification, fast routing
  Qwen3:8b   (M1/M2) → planning, drafting, routine execution [LOCAL]
  Sonnet+Advisor (M3) → Sonnet executor + Opus advisor [CLOUD]
  Opus       (M4) → trusted control plane, Red-tier only [CLOUD]

Each agent recognizes its capability ceiling and escalates rather
than guessing. The 5D score influences model routing: higher risk
→ higher model floor.

Cost × Risk coupling (§16):
  Rule A: Higher risk raises minimum model quality floor
  Rule B: Higher risk shrinks autonomy
  Rule C: Higher risk expands logging
  Rule D: Low cost does not justify weak safety
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .schema import Band, ModelClass, RoutingDecision


# ─── Concrete model mappings ───────────────────────────────────

@dataclass
class ModelConfig:
    """Maps abstract model class to concrete model identifiers."""
    model_class: ModelClass
    local_model: Optional[str] = None      # Ollama model name
    cloud_model: Optional[str] = None      # Anthropic model string
    cloud_advisor: Optional[str] = None    # Advisor model (for M3)
    use_advisor: bool = False              # Use Advisor Tool pattern
    max_tokens: int = 4096
    temperature: float = 0.3

    @property
    def is_local(self) -> bool:
        return self.local_model is not None and self.cloud_model is None

    @property
    def is_cloud(self) -> bool:
        return self.cloud_model is not None


# Default model configs for DotOS
DEFAULT_MODEL_CONFIGS: Dict[str, ModelConfig] = {
    "M0": ModelConfig(
        model_class=ModelClass.M0,
        local_model="phi4-mini",
        max_tokens=1024,
        temperature=0.1,
    ),
    "M1": ModelConfig(
        model_class=ModelClass.M1,
        local_model="qwen3:8b",
        max_tokens=4096,
        temperature=0.3,
    ),
    "M2": ModelConfig(
        model_class=ModelClass.M2,
        local_model="qwen3:8b",  # same model, /think mode
        max_tokens=8192,
        temperature=0.3,
    ),
    "M3": ModelConfig(
        model_class=ModelClass.M3,
        cloud_model="claude-sonnet-4-6",
        cloud_advisor="claude-opus-4-6",
        use_advisor=True,
        max_tokens=8192,
        temperature=0.3,
    ),
    "M4": ModelConfig(
        model_class=ModelClass.M4,
        cloud_model="claude-opus-4-6",
        max_tokens=8192,
        temperature=0.2,
    ),
}


# ─── Capability ceiling signals ─────────────────────────────────

@dataclass
class EscalationSignal:
    """Signal from an agent that it's hit its capability ceiling."""
    from_model: ModelClass
    to_model: ModelClass
    reason: str                        # why escalation is needed
    confidence: float = 0.0            # agent's self-assessed confidence (0-1)
    task_complexity: int = 0           # estimated complexity (1-5)
    domain_specificity: int = 0        # estimated domain depth (1-5)
    reasoning_depth: int = 0           # estimated reasoning steps (1-5)
    five_d_band: Optional[Band] = None # 5D risk band if available

    @property
    def should_escalate(self) -> bool:
        """Determine if escalation thresholds are met."""
        # Escalate if any signal exceeds the model's capability ceiling
        if self.confidence < 0.5:
            return True
        if self.task_complexity > 3 and self.from_model in (ModelClass.M0, ModelClass.M1):
            return True
        if self.reasoning_depth > 3 and self.from_model in (ModelClass.M0, ModelClass.M1):
            return True
        if self.five_d_band in (Band.ORANGE, Band.RED) and self.from_model != ModelClass.M4:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_model": str(self.from_model),
            "to_model": str(self.to_model),
            "reason": self.reason,
            "confidence": self.confidence,
            "task_complexity": self.task_complexity,
            "domain_specificity": self.domain_specificity,
            "reasoning_depth": self.reasoning_depth,
            "five_d_band": str(self.five_d_band) if self.five_d_band else None,
        }


# ─── Router ─────────────────────────────────────────────────────

class ModelRouter:
    """Routes tasks to the appropriate model based on 5D score + capability signals.

    Implements §19.3 routing table and §16 Cost × Risk coupling.
    """

    def __init__(
        self,
        configs: Optional[Dict[str, ModelConfig]] = None,
        cloud_enabled: bool = True,
    ) -> None:
        self.configs = configs or dict(DEFAULT_MODEL_CONFIGS)
        self.cloud_enabled = cloud_enabled

    def get_config(self, model_class: ModelClass) -> ModelConfig:
        """Get the concrete config for a model class."""
        return self.configs.get(str(model_class), self.configs["M1"])

    def route(
        self,
        routing_decision: RoutingDecision,
        escalation: Optional[EscalationSignal] = None,
    ) -> ModelConfig:
        """Resolve a RoutingDecision to a concrete ModelConfig.

        Respects:
          - Model floor (never downgrade below it)
          - Cloud availability
          - Escalation signals from agents
          - Cost × Risk coupling rules (§16)
        """
        target = routing_decision.selected_model

        # Apply escalation if present
        if escalation and escalation.should_escalate:
            target_order = [ModelClass.M0, ModelClass.M1, ModelClass.M2, ModelClass.M3, ModelClass.M4]
            target_idx = target_order.index(target)
            escalate_idx = target_order.index(escalation.to_model)
            if escalate_idx > target_idx:
                target = escalation.to_model

        # Never go below floor
        floor = routing_decision.model_floor
        floor_order = [ModelClass.M0, ModelClass.M1, ModelClass.M2, ModelClass.M3, ModelClass.M4]
        if floor_order.index(target) < floor_order.index(floor):
            target = floor

        # If cloud not enabled, cap at M2 (local)
        if not self.cloud_enabled and target in (ModelClass.M3, ModelClass.M4):
            target = ModelClass.M2

        return self.get_config(target)

    def classify_task(self, task_description: str) -> Dict[str, int]:
        """Return classification signals for a task.

        This is the M0 (phi) classification prompt pattern.
        Returns complexity, domain_specificity, reasoning_depth (1-5 each).

        NOTE: In production, this calls phi-4-mini via Ollama.
        Here we provide the prompt template and expected response format.
        """
        # This returns the prompt to send to phi for classification
        # The actual LLM call happens in the orchestration layer
        return {
            "prompt": f"""Classify this task on three dimensions (1-5 each):
- complexity: how many steps/tools needed? (1=trivial, 5=multi-system)
- domain_specificity: how specialized is the knowledge? (1=general, 5=expert)
- reasoning_depth: how many reasoning steps? (1=lookup, 5=multi-step analysis)

If ANY dimension > 3, output ESCALATE with reason.

Task: {task_description}

Respond in JSON: {{"complexity": N, "domain_specificity": N, "reasoning_depth": N, "escalate": bool, "reason": "..."}}""",
            "model": "phi4-mini",
            "max_tokens": 128,
            "temperature": 0.1,
        }

    def build_advisor_tool_config(self) -> Dict[str, Any]:
        """Return the Advisor Tool configuration for the Anthropic API.

        Per https://platform.claude.com/docs/en/agents-and-tools/tool-use/advisor-tool
        Executor: Sonnet 4.6, Advisor: Opus 4.6.
        Beta header: anthropic-beta: advisor-tool-2026-03-01
        """
        return {
            "type": "advisor_20260301",
            "name": "advisor",
            "model": "claude-opus-4-6",
            "max_uses": 3,  # per request, conservative default
            "caching": {
                "type": "ephemeral",
                "ttl": "5m",
            },
        }

    def build_api_headers(self) -> Dict[str, str]:
        """Return required API headers for Advisor Tool."""
        return {
            "anthropic-beta": "advisor-tool-2026-03-01",
        }
