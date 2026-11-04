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
        r"(?:ignore|disregard|forget|neglect|discard|override|erase)\s+"
        r"(?:(?:all|any|about|the|your|every)\s+){0,3}"
        r"(?:previous|prior|above|preceding|earlier|foregoing|last|former)\s+"
        r"(?:instructions?|prompts?|rules?|directives?|orders?|tasks?|assignments?|"
        r"commands?|information|text|messages?|context|guidelines?)"
        # "Forget everything before that" / "forget everything we discussed"
        r"|(?:ignore|disregard|forget|erase)\s+(?:all|everything|everthing)"
        r"(?:\s+(?:before|beforehand|prior|above|we\s+discussed|that|else))?"
        r"|(?:ignore|disregard)\s+(?:the\s+)?above\b"
        r"|(?:remove|leave|put)\s+all\s+(?:the\s+)?previous\s+"
        r"(?:tasks?|information|instructions?)\s+(?:out\s+of|behind|aside)"
        # German: the corpus is bilingual and the rules must be too.
        r"|(?:vergiss|ignoriere|missachte)\s+"
        r"(?:(?:alle|alles|jede|die|deine)\s+)?"
        r"(?:vorherigen?|vorangehenden?|obigen?|bisherigen?)?\s*"
        r"(?:anweisungen|aufgaben|anfragen|befehle|informationen|regeln)?"
        r"|vergiss\s+alles\b",
        "Attempts to void earlier instructions by asserting a newer imperative.",
    ),
    _rule(
        "PF002",
        "system_prompt_exfiltration",
        Severity.HIGH,
        r"(?:print|reveal|repeat|show|output|disclose|dump|tell|give|display)\s+"
        r"(?:me\s+)?(?:all\s+)?(?:of\s+)?(?:your|the)\s+"
        r"(?:full\s+|entire\s+|complete\s+|exact\s+|original\s+)?"
        r"(?:system\s+prompt|initial\s+instructions?|system\s+message|"
        r"prompt\s+text|prompt\s+texts|prompts?\b|instructions?\b)",
        "Requests the verbatim system prompt, often framed as verification or compliance.",
    ),
    _rule(
        "PF003",
        "persona_override",
        Severity.HIGH,
        r"you\s+are\s+(?:now\s+)?(?:DAN|AIM|STAN|DUDE)\b"
        r"|\b(?:pretend|imagine)\s+(?:that\s+)?you\s+(?:are|were)\b"
        r"|\bact\s+as\s+(?:a|an|the)?\s*\w"
        r"|\brole[\s-]?play\s+as\b"
        r"|\bfrom\s+now\s+on,?\s+you\s+(?:are|will\s+be)\b"
        r"|\byou\s+are\s+now\s+\w"
        r"|\bnow\s+you\s+are\s+\w"
        r"|\bjetzt\s+bist\s+du\b"
        r"|\b(?:du\s+bist\s+(?:jetzt|nun))\b"
        r"|\bverhalte\s+dich\s+wie\b"
        r"|\btu\s+so,?\s+als\b"
        r"|\bdeveloper\s+mode\s+enabled"
        r"|\bdebug\s+mode\b"
        r"|\b(?:unrestricted|unfiltered|jailbroken)\s+mode\b",
        "Tries to swap the assistant's identity, whether for a named jailbreak "
        "persona or an arbitrary character.",
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
        "PF010",
        "fictional_scaffold",
        Severity.MEDIUM,
        r"(?:are|is)\s+(?:two\s+)?(?:actors?|characters?)\b"
        r"|(?:people|persons)\s+who\s+are\s+acting\b"
        r"|in\s+a\s+(?:film|movie|play|story|scene|novel)\s+about\b"
        r"|there\s+is\s+a\s+scene\s+where\b"
        r"|(?:sind|ist)\s+(?:zwei\s+)?schauspieler\b"
        r"|in\s+einem\s+film\s+über\b",
        "Wraps the real request in a fictional frame so the model answers as a "
        "character rather than as itself.",
    ),
    _rule(
        "PF011",
        "praise_then_pivot",
        Severity.LOW,
        r"(?:excellent|great|fantastic|wonderful|perfect|well\s+done|congratulations|"
        r"simply\s+great|very\s+good|good\s+job|nicely\s+done)"
        r"[!.,]*\s*(?:performance|work|job)?[!.,]*\s*"
        r"(?:but\s+)?(?:now|next|then)\b"
        r"|that(?:'s| is)\s+(?:enough|done|ok)\.?\s*(?:but\s+)?now\b"
        r"|(?:sehr\s+gut|ausgezeichnet|wunderbar|toll)[!.,]*\s*(?:jetzt|nun)\b",
        "Opens with praise to establish rapport, then pivots to a substituted "
        "task. A social-engineering shape rather than a keyword.",
    ),
    _rule(
        "PF009",
        "task_reset",
        Severity.MEDIUM,
        r"forget\s+(?:about\s+)?(?:all\s+)?(?:the\s+)?(?:tasks?|assignments?|questions?)"
        r"|(?:now\s+)?(?:new|different)\s+tasks?\s+(?:follow|begin|start)"
        r"|focus\s+on\s+your\s+new\s+task"
        r"|(?:let'?s\s+|we\s+(?:will|'ll)\s+)?start\s+over\s+with\s+a\s+new\s+task"
        r"|that(?:'s| is)\s+enough\.?\s+now\b"
        r"|stop\.?\s*[-—]\s*I\s+urgently"
        r"|(?:now\s+)?(?:further|more|new)\s+(?:tasks?|instructions?)\s+"
        r"(?:are\s+)?(?:follow|followed|follows)\b"
        r"|konzentriere\s+dich\s+(?:jetzt\s+)?auf\s+(?:deine|die)\s+neue"
        r"|achtung\s*[-—]\s*stopp"
        r"|attention\s*[-—]\s*stop",
        "Declares the earlier task finished and substitutes a new one, a framing "
        "that carries many real injections without naming instructions at all.",
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
