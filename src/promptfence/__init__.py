"""promptfence — a layered, measurable defense against prompt injection."""

from .metrics import Outcome, Report, render_markdown, summarize
from .patterns import INPUT_RULES, OUTPUT_RULES, RULES_BY_ID, Rule, Severity
from .pipeline import Decision, Defense, Layer, Verdict
from .policy import HARDENED_SYSTEM_PROMPT, ToolBudget, ToolPolicy
from .scanners import InputScanner, Match, OutputScanner, ScanResult

__version__ = "0.1.0"

__all__ = [
    "Decision",
    "Defense",
    "HARDENED_SYSTEM_PROMPT",
    "INPUT_RULES",
    "InputScanner",
    "Layer",
    "Match",
    "OUTPUT_RULES",
    "Outcome",
    "OutputScanner",
    "RULES_BY_ID",
    "Report",
    "Rule",
    "ScanResult",
    "Severity",
    "ToolBudget",
    "ToolPolicy",
    "Verdict",
    "render_markdown",
    "summarize",
]
