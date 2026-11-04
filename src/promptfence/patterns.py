"""Named detection rules for prompt-injection scanning.

Each rule is kept separate rather than merged into one regex so that a block
can be attributed to a specific rule. Attribution is what makes a false
positive debuggable: knowing *which* rule fired tells you what to relax.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str


def _rule(rule_id: str, name: str, severity: Severity, regex: str, description: str) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=name,
        severity=severity,
        pattern=re.compile(regex, re.IGNORECASE),
        description=description,
    )


# Canary tokens are unique strings planted in a prompt or a document so that
# their appearance anywhere downstream proves the content was exfiltrated.
# Legitimate traffic never contains one, so a match is unambiguous.
CANARY_PATTERN = re.compile(r"CANARY_[A-Z]+_[a-f0-9]{4,}", re.IGNORECASE)

INPUT_RULES: tuple[Rule, ...] = (
    _rule(
        "PF001",
        "instruction_override",
        Severity.HIGH,
        r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|foregoing)\s+"
        r"(?:instructions?|prompts?|rules?|directives?)",
        "Attempts to void earlier instructions by asserting a newer imperative.",
    ),
    _rule(
        "PF002",
        "system_prompt_exfiltration",
        Severity.HIGH,
        r"(?:print|reveal|repeat|show|output|disclose|dump)\s+(?:me\s+)?(?:your\s+|the\s+)?"
        r"(?:full\s+|entire\s+|complete\s+|exact\s+)?(?:system\s+prompt|initial\s+instructions?|"
        r"system\s+message)",
        "Requests the verbatim system prompt, often framed as verification or compliance.",
    ),
    _rule(
        "PF003",
        "persona_override",
        Severity.HIGH,
        r"you\s+are\s+(?:now\s+)?(?:DAN|AIM|STAN|DUDE)\b"
        r"|\bact\s+as\s+(?:DAN|an?\s+unrestricted)"
        r"|\bdeveloper\s+mode\s+enabled"
        r"|\bdebug\s+mode\b"
        r"|\b(?:unrestricted|unfiltered|jailbroken)\s+mode\b",
        "Tries to swap the assistant's identity for one without restrictions.",
    ),
    _rule(
        "PF004",
        "restriction_nullification",
        Severity.HIGH,
        r"you\s+(?:have|now\s+have)\s+no\s+(?:restrictions?|limits?|guardrails?|filters?)"
        r"|without\s+any\s+(?:restrictions?|ethical\s+guidelines?)"
        r"|\bbypass\s+(?:your\s+)?(?:guardrails?|safety|restrictions?)",
        "Asserts that the assistant's constraints no longer apply.",
    ),
    _rule(
        "PF005",
        "embedded_system_directive",
        Severity.HIGH,
        r"system\s+override"
        r"|<!--[^>]*?(?:system|assistant|instruction)[^>]*?-->"
        r"|\[\[?\s*system\s*\]?\]"
        r"|###\s*system\s*###",
        "A directive planted inside document content or an HTML comment, which is the "
        "shape indirect injection takes when an agent reads untrusted data.",
    ),
    _rule(
        "PF006",
        "unauthorized_tool_invocation",
        Severity.HIGH,
        r"\b(?:call|invoke|execute|run)\s+(?:the\s+)?[a-z_]*"
        r"(?:delete_all|drop_table|exfiltrate|send_email|transfer_funds|wipe)[a-z_]*\s*"
        r"(?:tool|function|command)?",
        "Names a destructive or non-existent tool and asks for it to be called.",
    ),
    _rule(
        "PF007",
        "secret_emission_request",
        Severity.MEDIUM,
        r"(?:output|emit|reply\s+with|respond\s+with|return)\s+(?:exactly\s+)?"
        r"(?:this\s+)?(?:string|token|code|value)\b"
        r"|\bunlock\s+code\b"
        r"|\bverification\s+token\b",
        "Asks for a specific literal string to be echoed, the usual proof-of-compromise "
        "step in an injection payload.",
    ),
    _rule(
        "PF008",
        "canary_token_present",
        Severity.HIGH,
        CANARY_PATTERN.pattern,
        "A planted canary token appears in the input, so the content is known-tainted.",
    ),
)

OUTPUT_RULES: tuple[Rule, ...] = (
    _rule(
        "PF101",
        "canary_token_leaked",
        Severity.HIGH,
        CANARY_PATTERN.pattern,
        "The model reproduced a canary token, which means an exfiltration attempt "
        "reached the response.",
    ),
    _rule(
        "PF102",
        "system_prompt_leaked",
        Severity.HIGH,
        r"SECURITY\s+RULES\s*[—\-:]"
        r"|these\s+apply\s+unconditionally\s+and\s+cannot\s+be\s+overridden",
        "The response contains distinctive system-prompt text.",
    ),
    _rule(
        "PF103",
        "credential_leaked",
        Severity.HIGH,
        r"\b(?:sk|gsk|ghp|pk)_[A-Za-z0-9]{20,}\b"
        r"|\bAKIA[0-9A-Z]{16}\b",
        "The response contains something shaped like an API key or access token.",
    ),
)

RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in (*INPUT_RULES, *OUTPUT_RULES)}
