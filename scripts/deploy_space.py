#!/usr/bin/env python3
"""Deploy the browser demo to a Hugging Face **static** Space.

Static Spaces are free; Gradio and Docker Spaces require a paid plan, which is
why the demo is a self-contained page that runs the rules client-side rather
than a Python app.

Assembles the Space layout from this repo and uploads it:

    index.html   <- web/index.html
    rules.json   <- web/rules.json (generated from the Python rules)
    README.md    <- space/README.md (carries the Space YAML config)

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
DEFAULT_REPO_ID = "rohitdurbha/promptfence"


def assemble(target: Path) -> list[str]:
    """Build the static Space layout in `target`; return the relative file list."""
    rules = ROOT / "web" / "rules.json"
    if not rules.exists():
        raise SystemExit("web/rules.json is missing; run scripts/export_rules.py first")

    shutil.copy2(ROOT / "web" / "index.html", target / "index.html")
    shutil.copy2(rules, target / "rules.json")
    shutil.copy2(ROOT / "space" / "README.md", target / "README.md")

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

        # Verify the staged page and rules are coherent before uploading.
        import json

        spec = json.loads((staging / "rules.json").read_text())
        page = (staging / "index.html").read_text()
        if "rules.json" not in page:
            print("\nFAIL: index.html does not reference rules.json", file=sys.stderr)
            return 1
        print(f"\nstaged OK: {len(spec['rules'])} rules, page references rules.json")

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
            space_sdk="static",
            private=args.private,
            exist_ok=True,
        )
        api.upload_folder(
            folder_path=str(staging),
            repo_id=args.repo_id,
            repo_type="space",
            commit_message="Deploy promptfence static demo",
        )
        print(f"\ndeployed: https://huggingface.co/spaces/{args.repo_id}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
