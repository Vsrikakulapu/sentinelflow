"""Command line: ``python -m sentinelflow <command>``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinelflow.bundle import load_bundle, write_bundle
from sentinelflow.evaluation import format_breakdown, format_table, run
from sentinelflow.hypotheses.llm import client_from_env
from sentinelflow.pipeline import triage
from sentinelflow.report import to_markdown
from sentinelflow.scenarios import NEGATIVE, POSITIVE, expected_root_cause, generate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelflow", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    cmd = commands.add_parser("triage", help="triage an incident bundle directory")
    cmd.add_argument("bundle", type=Path)
    cmd.add_argument("--format", choices=["markdown", "json"], default="markdown")
    cmd.add_argument("--llm", action="store_true", help="also ask the configured LLM for extra hypotheses")

    cmd = commands.add_parser("eval", help="measure attribution accuracy on generated incidents")
    cmd.add_argument("--seeds", type=int, default=50)

    cmd = commands.add_parser("generate", help="write sample incident bundles")
    cmd.add_argument("--out", type=Path, default=Path("scenarios"))
    cmd.add_argument("--seed", type=int, default=0)

    args = parser.parse_args(argv)

    if args.command == "triage":
        report = triage(load_bundle(args.bundle), llm=client_from_env() if args.llm else None)
        print(report.model_dump_json(indent=2) if args.format == "json" else to_markdown(report))
    elif args.command == "eval":
        print(format_table(run(args.seeds)))
        print()
        print("Per scenario (correct / abstained / wrong):")
        print(format_breakdown(args.seeds))
    elif args.command == "generate":
        for kind in POSITIVE + NEGATIVE:
            write_bundle(generate(kind, args.seed), args.out / kind, expected_root_cause(kind))
            print(f"wrote {args.out / kind}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
