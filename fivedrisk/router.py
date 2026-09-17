"""5D Risk Governance Engine — Model routing and escalation.

Implements governance spec v0.3 §19 (Model Routing Policy) with
capability ceiling recognition and the Advisor Tool pattern.

ModelClass to example-model mapping (abstraction, not a model name;
operators map each class to whatever their stack supports):

  ===========  ============================  =========================================================
  ModelClass   Class description             Example models
  ===========  ============================  =========================================================
  M0           Embedding-only / classifier   OpenAI text-embedding-3, local SentenceTransformers
  M1           Cheap-fast inference          Claude Haiku, GPT-5-mini, Gemini Flash, local 8B (Ollama)
  M2           Balanced general use          Claude Sonnet, GPT-5, Gemini Pro
  M3           Frontier reasoning            Claude Opus, GPT-5.5, Gemini Ultra
  M4           Multi-model / ensemble        Operator-defined pipelines
  ===========  ============================  =========================================================

The DEFAULT_MODEL_CONFIGS below show one concrete mapping (local Ollama
plus Anthropic cloud). Override via ``ModelRouter(configs=...)`` to
match your own stack.

Each agent recognizes its capability ceiling and escalates rather
than guessing. The 5D risk band influences model routing: higher risk
implies a higher model floor.

Risk-based routing rules:
  - Higher risk raises the minimum model-quality floor
  - Higher risk shrinks autonomy
  - Higher risk expands logging
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
        # Low-5: tier is a property of the model CLASS (M0–M2 = local tier), not of
        # whether a concrete model name has been filled in. This keeps is_local /
        # is_cloud meaningful on the neutral default scaffold (names left None).
        return self.model_class in (ModelClass.M0, ModelClass.M1, ModelClass.M2)

    @property
    def is_cloud(self) -> bool:
        return self.model_class in (ModelClass.M3, ModelClass.M4)


# Default model configs — one concrete example mapping (M0–M4 → local + cloud
# models). This is a NEUTRAL scaffold: the M0–M4 classes + tuning knobs are the
# structure; the concrete model names are intentionally left unset (Low-5 — an
# OSS library must not ship opinionated model/agent choices). Populate the models
# for your own stack via `ModelRouter(configs=...)` or per-class `local_model` /
# `cloud_model` / `cloud_advisor`.
DEFAULT_MODEL_CONFIGS: Dict[str, ModelConfig] = {
    "M0": ModelConfig(
        model_class=ModelClass.M0,
        local_model=None,
        max_tokens=1024,
        temperature=0.1,
    ),
    "M1": ModelConfig(
        model_class=ModelClass.M1,
        local_model=None,
        max_tokens=4096,
        temperature=0.3,
    ),
    "M2": ModelConfig(
        model_class=ModelClass.M2,
        local_model=None,
        max_tokens=8192,
        temperature=0.3,
    ),
    "M3": ModelConfig(
        model_class=ModelClass.M3,
        cloud_model=None,
        cloud_advisor=None,
        use_advisor=True,
        max_tokens=8192,
        temperature=0.3,
    ),
    "M4": ModelConfig(
        model_class=ModelClass.M4,
        cloud_model=None,
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
    # Low-3: None = "no confidence reported" (does NOT escalate). The old default
    # of 0.0 made a default-constructed signal always escalate (0.0 < 0.5).
    confidence: Optional[float] = None  # agent's self-assessed confidence (0-1)
    task_complexity: int = 0           # estimated complexity (1-5)
    domain_specificity: int = 0        # estimated domain depth (1-5)
    reasoning_depth: int = 0           # estimated reasoning steps (1-5)
    five_d_band: Optional[Band] = None # 5D risk band if available

    @property
    def should_escalate(self) -> bool:
        """Determine if escalation thresholds are met."""
        # Escalate if any signal exceeds the model's capability ceiling
        if self.confidence is not None and self.confidence < 0.5:
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
    """Routes tasks to the appropriate model based on 5D risk band + capability signals.

    Risk-based model routing: higher risk raises the model floor.
    """

    def __init__(
        self,
        configs: Optional[Dict[str, ModelConfig]] = None,
        cloud_enabled: bool = True,
    ) -> None:
        self.configs = configs or dict(DEFAULT_MODEL_CONFIGS)
        self.cloud_enabled = cloud_enabled

    def get_config(self, model_class: ModelClass) -> ModelConfig:
        """Get the concrete config for a model class.

        Low-4: fall back to "M1" if present, otherwise ANY configured class,
        rather than raising KeyError when a custom `configs` omits "M1".
        """
        config = self.configs.get(str(model_class)) or self.configs.get("M1")
        if config is not None:
            return config
        if self.configs:
            return next(iter(self.configs.values()))
        raise ValueError("ModelRouter has no configs")

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
          - Risk-based routing rules (higher risk → higher floor)
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

    def classify_task(self, task_description: str) -> Dict[str, Any]:
        """Return the classification prompt template for a task.

        A lightweight-classifier prompt pattern that asks for complexity,
        domain_specificity, and reasoning_depth (1-5 each). Low-5: the return type
        is a mixed-type prompt dict (not Dict[str,int]); the actual model is the
        caller's choice — the `model` key is left None for you to fill in.
        """
        # The actual LLM call happens in the orchestration layer.
        return {
            "prompt": f"""Classify this task on three dimensions (1-5 each):
- complexity: how many steps/tools needed? (1=trivial, 5=multi-system)
- domain_specificity: how specialized is the knowledge? (1=general, 5=expert)
- reasoning_depth: how many reasoning steps? (1=lookup, 5=multi-step analysis)

If ANY dimension > 3, output ESCALATE with reason.

Task: {task_description}

Respond in JSON: {{"complexity": N, "domain_specificity": N, "reasoning_depth": N, "escalate": bool, "reason": "..."}}""",
            "model": None,  # Low-5: caller supplies the classifier model
            "max_tokens": 128,
            "temperature": 0.1,
        }

    def build_advisor_tool_config(self) -> Dict[str, Any]:
        """Return the Advisor Tool configuration for the Anthropic API.

        Per https://platform.claude.com/docs/en/agents-and-tools/tool-use/advisor-tool
        The executor and advisor models are the caller's choice (`model` is left
        None to fill in). Beta header via build_api_headers().
        """
        return {
            "type": "advisor_20260301",
            "name": "advisor",
            "model": None,  # Low-5: caller supplies the advisor model
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
