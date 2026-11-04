"""The defense pipeline: layers composed in the order they run."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .policy import HARDENED_SYSTEM_PROMPT, ToolBudget, ToolPolicy
from .scanners import InputScanner, OutputScanner, ScanResult


class Layer(str, Enum):
    """Which layer resolved a request. Ordered by position in the pipeline."""

    INPUT_SCAN = "input_scan"
    SYSTEM_PROMPT = "system_prompt"
    TOOL_POLICY = "tool_policy"
    TOOL_BUDGET = "tool_budget"
    OUTPUT_SCAN = "output_scan"
    NONE = "none"


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    layer: Layer
    rule_ids: tuple[str, ...] = ()
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    def as_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision.value,
            "layer": self.layer.value,
            "rule_ids": list(self.rule_ids),
            "reason": self.reason,
        }


REFUSAL = (
    "This request cannot be processed. It appears to contain instructions "
    "attempting to override the assistant's behaviour or extract protected content."
)


class Defense:
    """Composes the deterministic layers into a single decision.

    The model-dependent layer (the hardened system prompt) is represented but
    not executed here: `system_prompt` is handed to whatever client the caller
    uses. This keeps the pipeline importable, testable and demoable with no API
    key, which is the difference between a defense people can evaluate and one
    they take on trust.
    """

    def __init__(
        self,
        *,
        tool_policy: ToolPolicy | None = None,
        tool_call_cap: int = 6,
        system_prompt: str = HARDENED_SYSTEM_PROMPT,
        disabled_rules: frozenset[str] | None = None,
    ) -> None:
        self.disabled_rules = disabled_rules or frozenset()
        self.input_scanner = InputScanner(disabled_rules=self.disabled_rules)
        self.output_scanner = OutputScanner(disabled_rules=self.disabled_rules)
        self.tool_policy = tool_policy or ToolPolicy.of()
        self.tool_call_cap = tool_call_cap
        self.system_prompt = system_prompt

    def new_budget(self) -> ToolBudget:
        return ToolBudget(cap=self.tool_call_cap)

    def screen_input(self, text: str) -> Verdict:
        result: ScanResult = self.input_scanner.scan(text)
        if not result.blocked:
            return Verdict(Decision.ALLOW, Layer.NONE)
        top = result.top_match
        assert top is not None
        return Verdict(
            decision=Decision.BLOCK,
            layer=Layer.INPUT_SCAN,
            rule_ids=result.rule_ids,
            reason=f"{top.rule_name} matched ({top.rule_id})",
        )

    def screen_output(self, text: str) -> Verdict:
        result: ScanResult = self.output_scanner.scan(text)
        if not result.blocked:
            return Verdict(Decision.ALLOW, Layer.NONE)
        top = result.top_match
        assert top is not None
        return Verdict(
            decision=Decision.BLOCK,
            layer=Layer.OUTPUT_SCAN,
            rule_ids=result.rule_ids,
            reason=f"{top.rule_name} matched ({top.rule_id})",
        )

    def check_tool(self, tool_name: str, budget: ToolBudget) -> Verdict:
        if not self.tool_policy.permits(tool_name):
            return Verdict(
                decision=Decision.BLOCK,
                layer=Layer.TOOL_POLICY,
                reason=f"tool {tool_name!r} is not on the allow-list",
            )
        if not budget.request():
            return Verdict(
                decision=Decision.BLOCK,
                layer=Layer.TOOL_BUDGET,
                reason=f"tool budget of {budget.cap} calls exhausted",
            )
        return Verdict(Decision.ALLOW, Layer.NONE)

    def evaluate(self, text: str, model_output: str | None = None) -> Verdict:
        """Run the deterministic layers end to end.

        `model_output` is optional so the pipeline can be evaluated without a
        model: with it absent, only the input boundary is exercised.
        """
        verdict = self.screen_input(text)
        if verdict.blocked:
            return verdict
        if model_output is not None:
            verdict = self.screen_output(model_output)
            if verdict.blocked:
                return verdict
        return Verdict(Decision.ALLOW, Layer.NONE)
