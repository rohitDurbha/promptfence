#!/usr/bin/env python3
"""Evaluate the defense against a corpus and write results plus a report.

    python -m benchmarks.run_bench --source fixtures
    python -m benchmarks.run_bench --source jbb --out results/jbb
    python -m benchmarks.run_bench --source injecagent --path data/injecagent.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from promptfence import Defense, Outcome, render_markdown, summarize

from .loaders import Case, load_fixtures, load_injecagent, load_jbb_behaviors

TITLES = {
    "fixtures": "promptfence — bundled fixtures",
    "jbb": "promptfence — JailbreakBench JBB-Behaviors (benign split, false-positive corpus)",
    "jbb-scope": "promptfence — JBB-Behaviors scope check (harmful split is out of scope)",
    "injecagent": "promptfence — InjecAgent",
}


def gather(source: str, path: str | None) -> list[Case]:
    if source == "fixtures":
        return load_fixtures()
    if source == "jbb":
        return load_jbb_behaviors()
    if source == "jbb-scope":
        return load_jbb_behaviors(include_harmful=True)
    if source == "injecagent":
        if not path:
            raise SystemExit("--source injecagent requires --path to the downloaded file")
        return load_injecagent(path)
    raise SystemExit(f"unknown source {source!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default="fixtures",
        choices=sorted(TITLES),
        help="which corpus to evaluate against (default: fixtures, needs no network)",
    )
    parser.add_argument("--path", help="local file for corpora distributed as files")
    parser.add_argument(
        "--out",
        default="results",
        help="directory for results.jsonl and report.md (default: results)",
    )
    parser.add_argument(
        "--tool-cap",
        type=int,
        default=6,
        help="tool-call budget per request (default: 6)",
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="exclude a rule, repeatable; use it to ablate a rule and see what it "
        "was contributing (e.g. --disable-rule PF008)",
    )
    parser.add_argument(
        "--fail-over-fpr",
        type=float,
        default=None,
        help="exit non-zero if the false-positive rate exceeds this threshold",
    )
    parser.add_argument(
        "--fail-over-asr",
        type=float,
        default=None,
        help="exit non-zero if the attack success rate exceeds this threshold",
    )
    args = parser.parse_args(argv)

    cases = gather(args.source, args.path)
    disabled = frozenset(args.disable_rule)
    defense = Defense(tool_call_cap=args.tool_cap, disabled_rules=disabled)

    outcomes: list[Outcome] = []
    for case in cases:
        verdict = defense.screen_input(case.text)
        outcomes.append(
            Outcome(
                case_id=case.case_id,
                is_attack=case.is_attack,
                verdict=verdict,
                source=case.source,
                attack_type=case.attack_type,
            )
        )

    report = summarize(outcomes)

    title = TITLES[args.source]
    if disabled:
        title += f" (rules disabled: {', '.join(sorted(disabled))})"

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    with (out_dir / "results.jsonl").open("w") as handle:
        for outcome in outcomes:
            handle.write(
                json.dumps(
                    {
                        "case_id": outcome.case_id,
                        "source": outcome.source,
                        "is_attack": outcome.is_attack,
                        "attack_type": outcome.attack_type,
                        **outcome.verdict.as_dict(),
                    }
                )
                + "\n"
            )

    (out_dir / "summary.json").write_text(json.dumps(report.as_dict(), indent=2) + "\n")
    (out_dir / "report.md").write_text(render_markdown(report, title))

    print(render_markdown(report, title))
    print(f"wrote {out_dir}/results.jsonl, summary.json, report.md")

    status = 0
    if args.fail_over_fpr is not None and report.false_positive_rate > args.fail_over_fpr:
        print(
            f"FAIL: false-positive rate {report.false_positive_rate:.3f} "
            f"exceeds threshold {args.fail_over_fpr:.3f}",
            file=sys.stderr,
        )
        status = 1
    if args.fail_over_asr is not None and report.attack_success_rate > args.fail_over_asr:
        print(
            f"FAIL: attack success rate {report.attack_success_rate:.3f} "
            f"exceeds threshold {args.fail_over_asr:.3f}",
            file=sys.stderr,
        )
        status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
