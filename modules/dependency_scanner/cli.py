import argparse
from pathlib import Path

from .scanner import run


def main(argv=None):
    parser = argparse.ArgumentParser(prog="dependency_scanner")
    parser.add_argument("path", help="project directory to scan")
    parser.add_argument("--offline", action="store_true",
                        help="use cached OSV responses only")
    parser.add_argument("--cache-dir", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    result = run(args.path, {
        "offline": args.offline,
        "osv_cache_dir": args.cache_dir,
    })

    output = result.model_dump_json(indent=2)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 1 if result.status == "error" else 0
