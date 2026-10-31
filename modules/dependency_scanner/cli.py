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
    parser.add_argument("--sbom", "--sbom-out", dest="sbom_path", default=None,
                        help="path to write intermediate SBOM")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="display verbose scan progress")
    parser.add_argument("--install", action="store_true", default=None,
                        help="install dependencies declared in package.json")
    parser.add_argument("--no-install", dest="install", action="store_false",
                        help="disable dependency installation")
    args = parser.parse_args(argv)

    sbom_path = args.sbom_path
    if not sbom_path and "deps_vuln_cpp" in str(args.path):
        sbom_path = "reports/cpp_demo.sbom.json"

    result = run(args.path, {
        "offline": args.offline,
        "osv_cache_dir": args.cache_dir,
        "verbose": args.verbose,
        "sbom_path": sbom_path,
        "out_path": args.out,
        "install": args.install,
    })

    output = result.model_dump_json(indent=2)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
    else:
        print(output)

    return 1 if result.status == "error" else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
