import argparse
import json
import sys

from . import runner


def main():
    ap = argparse.ArgumentParser(
        prog='python -m modules.build_integrity'
    )

    ap.add_argument('project_path')
    ap.add_argument('--recipe', default='buildguard.yml')

    ap.add_argument(
        '--allow-unpinned',
        action='store_true',
        help='dev only: allow an image tag'
    )

    ap.add_argument('--timeout', type=int, default=120)

    ap.add_argument(
        '--release',
        action='store_true',
        help='build the trusted artifact into dist/ and write release_manifest.json'
    )

    ap.add_argument(
        '--manifest',
        help='release_manifest.json to verify against'
    )

    ap.add_argument(
        '--distributed',
        help='distributed file to verify'
    )

    ap.add_argument(
        '--verify-only',
        action='store_true',
        help='only hash --distributed against --manifest (no Docker needed)'
    )

    a = ap.parse_args()

    opts = {
        'recipe_path': a.recipe,
        'allow_unpinned': a.allow_unpinned,
        'docker_timeout': a.timeout
    }

    if a.release:
        try:
            print(
                json.dumps(
                    runner.create_release(a.project_path, opts),
                    indent=2
                )
            )

        except runner.ReleaseError as e:
            print(
                json.dumps(
                    {'error': e.code, 'message': str(e)},
                    indent=2
                )
            )
            sys.exit(1)

        return

    if a.verify_only:
        print(
            json.dumps(
                runner.verify(a.manifest, a.distributed),
                indent=2
            )
        )
        return

    opts['manifest_path'], opts['distributed_artifact'] = (
        a.manifest,
        a.distributed
    )

    print(
        runner.run(a.project_path, opts).model_dump_json(indent=2)
    )


if __name__ == '__main__':
    main()
