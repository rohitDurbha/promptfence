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


def load_deepset_prompt_injections(split: str | None = None) -> list[Case]:
    """deepset/prompt-injections (Apache-2.0) — the primary ASR + FPR corpus.

    662 examples across both splits, labelled 1 for injection and 0 for benign:
    263 injections and 399 benign. This is the corpus that actually measures
    attack success rate for this threat model, because every positive example
    is a genuine attempt to override instructions or extract context, and the
    negatives are ordinary requests.

    It is also multilingual in places, which is a known weakness of the
    English-only rules and shows up honestly in the numbers.

    Pass ``split`` to get "train" or "test" alone. Rules are developed against
    train and reported on test, so the headline numbers are not fitted to the
    cases they describe.
    """
    try:
        from datasets import load_dataset
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "load_deepset_prompt_injections needs 'datasets': pip install datasets"
        ) from exc

    cases: list[Case] = []
    ds = load_dataset("deepset/prompt-injections")
    wanted = [split] if split else list(ds)
    for split_name in wanted:
        for index, row in enumerate(ds[split_name]):
            text = _first_present(row, ("text", "prompt"))
            if text is None:
                raise RuntimeError(
                    f"No text column in deepset/prompt-injections {split_name!r}; "
                    f"columns seen: {sorted(row)}"
                )
            label = row.get("label")
            is_attack = str(label) == "1"
            cases.append(
                Case(
                    case_id=f"deepset-{split_name}-{index:04d}",
                    text=text,
                    is_attack=is_attack,
                    source="deepset_prompt_injections",
                    attack_type="prompt_injection" if is_attack else "",
                )
            )
    return cases


def load_gandalf_ignore_instructions() -> list[Case]:
    """Lakera/gandalf_ignore_instructions (MIT) — real in-the-wild injections.

    1,000 prompts players actually submitted to Lakera's Gandalf game while
    trying to extract a hidden password, filtered by embedding similarity to
    "ignore all previous instructions" and de-duplicated.

    Attack-class only, so pair it with a benign corpus to get a false-positive
    rate. Lakera notes the selection was automatic and a few samples may not be
    true injections, so treat the attack success rate here as approximate.
    """
    try:
        from datasets import load_dataset
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "load_gandalf_ignore_instructions needs 'datasets': pip install datasets"
        ) from exc

    cases: list[Case] = []
    ds = load_dataset("Lakera/gandalf_ignore_instructions")
    for split_name in ds:
        for index, row in enumerate(ds[split_name]):
            text = _first_present(row, ("text", "prompt"))
            if text is None:
                raise RuntimeError(
                    f"No text column in gandalf_ignore_instructions {split_name!r}; "
                    f"columns seen: {sorted(row)}"
                )
            cases.append(
                Case(
                    case_id=f"gandalf-{split_name}-{index:04d}",
                    text=text,
                    is_attack=True,
                    source="gandalf_ignore_instructions",
                    attack_type="in_the_wild_injection",
                )
            )
    return cases
