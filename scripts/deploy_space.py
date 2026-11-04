#!/usr/bin/env python3
"""Deploy the Gradio demo to a Hugging Face Space.

Assembles a flat Space layout from this repo and uploads it:

    app.py            <- app/app.py
    src/promptfence/   <- the package
    data/              <- offline fixtures used by the examples
    requirements.txt
    README.md          <- space/README.md (carries the Space YAML config)

Usage:

    export HF_TOKEN=hf_...            # a write token
    python scripts/deploy_space.py                       # default repo id
    python scripts/deploy_space.py --repo-id user/name   # override

The token is read from the environment only; it is never written to disk or
echoed. Nothing is uploaded until the Space repo exists, and --dry-run shows
the exact file list first.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO_ID = "rohitDurbha/promptfence"


def assemble(target: Path) -> list[str]:
    """Build the flat Space layout in `target`; return the relative file list."""
    shutil.copy2(ROOT / "app" / "app.py", target / "app.py")
    shutil.copy2(ROOT / "requirements.txt", target / "requirements.txt")
    shutil.copy2(ROOT / "space" / "README.md", target / "README.md")

    shutil.copytree(
        ROOT / "src" / "promptfence",
        target / "src" / "promptfence",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (target / "data").mkdir(exist_ok=True)
    for name in ("fixtures_attack.jsonl", "fixtures_benign.jsonl"):
        shutil.copy2(ROOT / "data" / name, target / "data" / name)

    return sorted(
        str(p.relative_to(target)) for p in target.rglob("*") if p.is_file()
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", default=DEFAULT_REPO_ID, help="HF Space repo id")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="assemble and list files without creating or uploading anything",
    )
    parser.add_argument("--private", action="store_true", help="create the Space private")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        files = assemble(staging)

        print(f"Space layout for {args.repo_id}:")
        for name in files:
            print(f"  {name}")

        # Verify the flattened layout actually imports before uploading.
        sys.path.insert(0, str(staging / "src"))
        try:
            import promptfence  # noqa: F401
        except Exception as exc:  # pragma: no cover - defensive
            print(f"\nFAIL: staged package does not import: {exc}", file=sys.stderr)
            return 1
        finally:
            sys.path.pop(0)
        print("\nstaged package imports OK")

        if args.dry_run:
            print("dry run — nothing uploaded")
            return 0

        token = os.environ.get("HF_TOKEN")
        if not token:
            print(
                "\nHF_TOKEN is not set. Create a write token at "
                "https://huggingface.co/settings/tokens and export it:\n"
                "    export HF_TOKEN=hf_...",
                file=sys.stderr,
            )
            return 2

        try:
            from huggingface_hub import HfApi
        except ImportError:
            print(
                "\nhuggingface_hub is required: pip install huggingface_hub",
                file=sys.stderr,
            )
            return 2

        api = HfApi(token=token)
        api.create_repo(
            repo_id=args.repo_id,
            repo_type="space",
            space_sdk="gradio",
            private=args.private,
            exist_ok=True,
        )
        api.upload_folder(
            folder_path=str(staging),
            repo_id=args.repo_id,
            repo_type="space",
            commit_message="Deploy promptfence demo",
        )
        print(f"\ndeployed: https://huggingface.co/spaces/{args.repo_id}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
