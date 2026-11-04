"""Adapters that turn public attack corpora into a common Case shape.

Each loader is independent so that a corpus moving or changing schema breaks
one adapter rather than the benchmark. The bundled fixtures loader needs no
network, which is what lets CI run the full pipeline on every push.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass(frozen=True)
class Case:
    case_id: str
    text: str
    is_attack: bool
    source: str
    attack_type: str = ""


def _first_present(row: dict, candidates: tuple[str, ...]) -> str | None:
    for key in candidates:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def load_fixtures() -> list[Case]:
    """The bundled offline corpus: hand-written attacks plus benign controls.

    Small by design. Its job is to keep the pipeline honest in CI, not to
    stand in for a real benchmark.
    """
    cases: list[Case] = []

    attack_path = DATA_DIR / "fixtures_attack.jsonl"
    for line in attack_path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        cases.append(
            Case(
                case_id=row["input_id"],
                text=row["content"],
                is_attack=True,
                source="fixtures",
                attack_type=row.get("attack_type", ""),
            )
        )

    benign_path = DATA_DIR / "fixtures_benign.jsonl"
    for line in benign_path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        cases.append(
            Case(
                case_id=row["input_id"],
                text=row["content"],
                is_attack=False,
                source="fixtures",
            )
        )

    return cases


def load_jbb_behaviors(include_harmful: bool = False) -> list[Case]:
    """JailbreakBench JBB-Behaviors (MIT licence) — a false-positive corpus.

    100 harmful behaviours drawn from AdvBench and the TDC/HarmBench red-teaming
    track, plus a matched benign split of 100.

    By default only the **benign** split is loaded, and that is a deliberate
    scoping decision rather than a convenience. JBB's harmful split contains
    content-misuse requests ("write a defamatory article about..."), which is a
    different threat model from prompt injection: nothing in those prompts tries
    to override an agent's instructions or exfiltrate its context. A prompt-
    injection scanner should not block them, and promptfence does not — measured
    at 0 of 100. Scoring them as attack success rate would misreport correct
    behaviour as total failure.

    What the benign split is genuinely good for is the false-positive rate. Its
    prompts are topically adjacent to the harmful ones, so they are a far harder
    test of over-blocking than neutral filler text.

    Pass ``include_harmful=True`` to load the harmful split too, labelled with
    attack_type "out_of_scope_content_harm", if you want to re-verify that
    scoping claim yourself.

    Requires `datasets`. Raises with the observed column names if the schema has
    moved, rather than guessing.
    """
    try:
        from datasets import load_dataset
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "load_jbb_behaviors needs the 'datasets' package: pip install datasets"
        ) from exc

    wanted: tuple[tuple[str, bool], ...] = (("benign", False),)
    if include_harmful:
        wanted = (("harmful", True), ("benign", False))

    cases: list[Case] = []
    for split_name, is_attack in wanted:
        ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split=split_name)
        for index, row in enumerate(ds):
            text = _first_present(row, ("Goal", "goal", "Behavior", "behavior", "prompt"))
            if text is None:
                raise RuntimeError(
                    "Could not find a prompt column in JBB-Behaviors "
                    f"split {split_name!r}; columns seen: {sorted(row)}"
                )
            cases.append(
                Case(
                    case_id=f"jbb-{split_name}-{index:03d}",
                    text=text,
                    is_attack=is_attack,
                    source="jbb_behaviors",
                    attack_type=(
                        "out_of_scope_content_harm"
                        if is_attack
                        else str(_first_present(row, ("Category", "category")) or "")
                    ),
                )
            )
    return cases


def load_injecagent(path: str | Path) -> list[Case]:
    """InjecAgent test cases from a local JSON or JSONL file.

    InjecAgent is distributed from its GitHub repository rather than as a
    single canonical Hub dataset, so this adapter reads whatever file you
    fetched. It covers direct-harm and data-stealing objectives across a set
    of user tools and attacker tools; the attacker instruction is the field
    this defense is screening.
    """
    path = Path(path)
    raw = path.read_text()

    rows: list[dict]
    if path.suffix == ".jsonl":
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    else:
        parsed = json.loads(raw)
        rows = parsed if isinstance(parsed, list) else [parsed]

    cases: list[Case] = []
    for index, row in enumerate(rows):
        text = _first_present(
            row,
            (
                "Attacker Instruction",
                "attacker_instruction",
                "Attacker Tool Parameters",
                "Tool Response",
                "tool_response",
                "content",
            ),
        )
        if text is None:
            raise RuntimeError(
                "Could not find an attack-text column in InjecAgent row "
                f"{index}; columns seen: {sorted(row)}"
            )
        cases.append(
            Case(
                case_id=f"injecagent-{index:04d}",
                text=text,
                is_attack=True,
                source="injecagent",
                attack_type=str(
                    _first_present(row, ("Attacker Tools", "attack_type", "Setting")) or ""
                ),
            )
        )
    return cases


def load_jsonl_corpus(path: str | Path, *, is_attack: bool, source: str) -> list[Case]:
    """Generic adapter so any JSONL of {id, text} can be benchmarked."""
    path = Path(path)
    cases: list[Case] = []
    for index, line in enumerate(path.read_text().splitlines()):
        if not line.strip():
            continue
        row = json.loads(line)
        text = _first_present(row, ("text", "content", "prompt", "goal"))
        if text is None:
            raise RuntimeError(
                f"No text column in {path} row {index}; columns seen: {sorted(row)}"
            )
        cases.append(
            Case(
                case_id=str(row.get("id") or row.get("input_id") or f"{source}-{index:04d}"),
                text=text,
                is_attack=is_attack,
                source=source,
                attack_type=str(row.get("attack_type", "")),
            )
        )
    return cases
