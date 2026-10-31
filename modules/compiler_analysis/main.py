"""Command line entry point for Module C."""

import argparse
import json

from . import run

parser = argparse.ArgumentParser(description="BuildGuard Module C: compiler analysis (C, Linux ELF)")
parser.add_argument("sample")
parser.add_argument("--project-cc", default=None, help="override the project compiler command")
parser.add_argument("--out-dir", default=None, help="keep lab artifacts here")
parser.add_argument("--opt-level", default="-O0", help="experiment only: -O0 (default), -O1, -O2, -O3, -Os")
parser.add_argument("--strip", action="store_true", help="experiment only: strip symbols to test the limitation")


def main():
    args = parser.parse_args()
    options = {"opt_level": args.opt_level, "strip": args.strip}
    if args.project_cc:
        options["project_cc"] = args.project_cc
    if args.out_dir:
        options["out_dir"] = args.out_dir
    print(json.dumps(run(args.sample, options), indent=2))


if __name__ == "__main__":
    main()
