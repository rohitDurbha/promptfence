#!/usr/bin/env python3
"""Verify the browser implementation agrees with the Python one.

The static demo re-implements scanning in JavaScript against the exported
rules. Two implementations of the same rules will drift unless something
checks, so this compares blocked/rule_ids/spans case by case and fails loudly
on any difference.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from promptfence import InputScanner  # noqa: E402

sys.path.insert(0, str(ROOT))
from benchmarks.loaders import load_fixtures  # noqa: E402


def python_verdicts() -> list[dict[str, object]]:
    scanner = InputScanner()
    rows: list[dict[str, object]] = []
    for case in load_fixtures():
        result = scanner.scan(case.text)
        rows.append(
            {
                "case_id": case.case_id,
                "is_attack": case.is_attack,
                "blocked": result.blocked,
                "rule_ids": list(result.rule_ids),
                "spans": [list(m.span) for m in result.matches],
            }
        )
    return rows


def js_verdicts() -> list[dict[str, object]]:
    proc = subprocess.run(
        ["node", str(ROOT / "scripts" / "js_verdicts.mjs")],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit("node failed; is node installed?")
    return json.loads(proc.stdout)


def main() -> int:
    py = {row["case_id"]: row for row in python_verdicts()}
    js = {row["case_id"]: row for row in js_verdicts()}

    if set(py) != set(js):
        print(
            f"FAIL: case sets differ. python-only={sorted(set(py) - set(js))} "
            f"js-only={sorted(set(js) - set(py))}",
            file=sys.stderr,
        )
        return 1

    failures = 0
    for case_id in sorted(py):
        a, b = py[case_id], js[case_id]
        for field in ("blocked", "rule_ids", "spans"):
            if a[field] != b[field]:
                print(
                    f"FAIL {case_id}: {field} python={a[field]!r} js={b[field]!r}",
                    file=sys.stderr,
                )
                failures += 1

    if failures:
        print(f"\n{failures} mismatch(es) between Python and JavaScript", file=sys.stderr)
        return 1

    print(f"parity OK: {len(py)} cases, identical verdicts, rules and spans")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
