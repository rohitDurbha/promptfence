"""Deterministic scanners for the input and output boundaries.

These require no model call, so they run in microseconds and cost nothing.
That matters for a defense: a layer that needs an LLM to decide whether to
call an LLM is a layer you will turn off under load.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .patterns import INPUT_RULES, OUTPUT_RULES, Rule, Severity


@dataclass(frozen=True)
class Match:
    rule_id: str
    rule_name: str
    severity: Severity
    span: tuple[int, int]
    excerpt: str


@dataclass(frozen=True)
class ScanResult:
    blocked: bool
    matches: tuple[Match, ...] = field(default_factory=tuple)

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(m.rule_id for m in self.matches)

    @property
    def top_match(self) -> Match | None:
        """The highest-severity match, for single-reason reporting."""
        if not self.matches:
            return None
        order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        return min(self.matches, key=lambda m: order[m.severity])


class _RegexScanner:
    """Shared machinery: run every rule and collect all matches."""

    def __init__(
        self,
        rules: tuple[Rule, ...],
        excerpt_chars: int = 60,
        disabled_rules: frozenset[str] | None = None,
    ) -> None:
        self._disabled = disabled_rules or frozenset()
        self._rules = tuple(r for r in rules if r.rule_id not in self._disabled)
        self._excerpt_chars = excerpt_chars

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    @property
    def disabled_rules(self) -> frozenset[str]:
        """Rule ids excluded from this scanner.

        Disabling a rule is how you measure what it was actually contributing.
        A defense whose score collapses when one rule is removed is relying on
        that rule, which is worth knowing before you trust the headline number.
        """
        return self._disabled

    def scan(self, text: str) -> ScanResult:
        if not text:
            return ScanResult(blocked=False)

        matches: list[Match] = []
        for rule in self._rules:
            found = rule.pattern.search(text)
            if found is None:
                continue
            start, end = found.span()
            excerpt = text[start:end][: self._excerpt_chars]
            matches.append(
                Match(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    span=(start, end),
                    excerpt=excerpt,
                )
            )

        return ScanResult(blocked=bool(matches), matches=tuple(matches))


class InputScanner(_RegexScanner):
    """Screens untrusted text before it is ever placed in a prompt."""

    def __init__(
        self,
        excerpt_chars: int = 60,
        disabled_rules: frozenset[str] | None = None,
    ) -> None:
        super().__init__(INPUT_RULES, excerpt_chars, disabled_rules)


class OutputScanner(_RegexScanner):
    """Final check on a generated response before it is returned to a caller.

    The output scanner exists because the input scanner will miss attacks. It
    is the layer that converts "the model was manipulated" into "the caller
    never saw the result".
    """

    def __init__(
        self,
        excerpt_chars: int = 60,
        disabled_rules: frozenset[str] | None = None,
    ) -> None:
        super().__init__(OUTPUT_RULES, excerpt_chars, disabled_rules)
