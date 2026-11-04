"""Attack success rate, false-positive rate, and per-layer attribution.

A defense reported only as "blocked 5 of 5 attacks" is not evaluable. The
number that decides whether anyone can deploy it is how much legitimate
traffic it also blocks.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .pipeline import Layer, Verdict


@dataclass(frozen=True)
class Outcome:
    case_id: str
    is_attack: bool
    verdict: Verdict
    source: str = ""
    attack_type: str = ""


@dataclass
class Report:
    attacks_total: int = 0
    attacks_blocked: int = 0
    benign_total: int = 0
    benign_blocked: int = 0
    by_layer: Counter[str] = field(default_factory=Counter)
    by_rule: Counter[str] = field(default_factory=Counter)
    by_attack_type: dict[str, tuple[int, int]] = field(default_factory=dict)
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)

    @property
    def attack_success_rate(self) -> float:
        """Share of attacks that got through. Lower is better."""
        if self.attacks_total == 0:
            return 0.0
        return (self.attacks_total - self.attacks_blocked) / self.attacks_total

    @property
    def block_rate(self) -> float:
        if self.attacks_total == 0:
            return 0.0
        return self.attacks_blocked / self.attacks_total

    @property
    def false_positive_rate(self) -> float:
        """Share of benign traffic wrongly blocked. Lower is better."""
        if self.benign_total == 0:
            return 0.0
        return self.benign_blocked / self.benign_total

    def as_dict(self) -> dict[str, object]:
        return {
            "attacks_total": self.attacks_total,
            "attacks_blocked": self.attacks_blocked,
            "attack_success_rate": round(self.attack_success_rate, 4),
            "block_rate": round(self.block_rate, 4),
            "benign_total": self.benign_total,
            "benign_blocked": self.benign_blocked,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "blocks_by_layer": dict(self.by_layer),
            "blocks_by_rule": dict(self.by_rule),
            "block_rate_by_attack_type": {
                k: {"blocked": b, "total": t, "rate": round(b / t, 4) if t else 0.0}
                for k, (b, t) in sorted(self.by_attack_type.items())
            },
            "false_positive_ids": self.false_positives,
            "false_negative_ids": self.false_negatives,
        }


def summarize(outcomes: list[Outcome]) -> Report:
    report = Report()
    per_type: dict[str, list[int]] = {}

    for out in outcomes:
        blocked = out.verdict.blocked
        if out.is_attack:
            report.attacks_total += 1
            if blocked:
                report.attacks_blocked += 1
                report.by_layer[out.verdict.layer.value] += 1
                for rid in out.verdict.rule_ids:
                    report.by_rule[rid] += 1
            else:
                report.false_negatives.append(out.case_id)
            if out.attack_type:
                slot = per_type.setdefault(out.attack_type, [0, 0])
                slot[1] += 1
                if blocked:
                    slot[0] += 1
        else:
            report.benign_total += 1
            if blocked:
                report.benign_blocked += 1
                report.false_positives.append(out.case_id)
                report.by_layer[f"{out.verdict.layer.value}|false_positive"] += 1

    report.by_attack_type = {k: (v[0], v[1]) for k, v in per_type.items()}
    return report


def render_markdown(report: Report, title: str) -> str:
    d = report.as_dict()
    lines = [
        f"# {title}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attacks evaluated | {d['attacks_total']} |",
        f"| Attacks blocked | {d['attacks_blocked']} |",
        f"| **Attack success rate** | **{report.attack_success_rate:.1%}** |",
        f"| Benign evaluated | {d['benign_total']} |",
        f"| Benign wrongly blocked | {d['benign_blocked']} |",
        f"| **False-positive rate** | **{report.false_positive_rate:.1%}** |",
        "",
    ]

    if report.by_attack_type:
        lines += ["## Block rate by attack type", "", "| Attack type | Blocked | Total | Rate |", "|---|---|---|---|"]
        for name, (blocked, total) in sorted(report.by_attack_type.items()):
            rate = blocked / total if total else 0.0
            lines.append(f"| {name} | {blocked} | {total} | {rate:.0%} |")
        lines.append("")

    if report.by_rule:
        lines += ["## Blocks attributed to each rule", "", "| Rule | Blocks |", "|---|---|"]
        for rid, count in report.by_rule.most_common():
            lines.append(f"| {rid} | {count} |")
        lines.append("")

    if report.false_positives:
        lines += ["## False positives", "", "These benign cases were blocked and are the cost of the current rules:", ""]
        lines += [f"- `{cid}`" for cid in report.false_positives]
        lines.append("")

    if report.false_negatives:
        lines += ["## False negatives", "", "These attacks were not blocked:", ""]
        lines += [f"- `{cid}`" for cid in report.false_negatives]
        lines.append("")

    return "\n".join(lines)
