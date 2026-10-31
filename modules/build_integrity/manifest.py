import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from backend.schemas import Evidence, Finding
from . import diagnose
from .hashing import sha256_file


def write_manifest(project_path, recipe, outcome, commit):
    name = os.path.basename(recipe.artifact)

    trusted_dir = Path(project_path) / '.buildguard' / 'trusted'
    trusted_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(outcome.artifact_path, trusted_dir / name)

    data = {
        'manifest_version': 1,
        'artifact_name': name,
        'sha256': outcome.sha256,
        'size': outcome.size,
        'recipe_sha256': recipe.raw_sha256,
        'image': recipe.image,
        'git_commit': commit,
        'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'trusted_copy': f'.buildguard/trusted/{name}',
    }

    path = Path(project_path) / 'release_manifest.json'
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')

    return str(path)


def verify_artifact(manifest_path, distributed_path):
    mp = Path(manifest_path)
    data = json.loads(mp.read_text(encoding='utf-8'))

    dist_hash = sha256_file(distributed_path)
    same = dist_hash == data['sha256']

    out = {
        'result': (
            'DISTRIBUTED_MATCHES_TRUSTED'
            if same
            else 'DISTRIBUTED_DIFFERS_FROM_TRUSTED'
        ),
        'artifact_name': data['artifact_name'],
        'trusted_sha256': data['sha256'],
        'distributed_sha256': dist_hash,
        'trusted_size': data['size'],
        'distributed_size': os.path.getsize(distributed_path),
        'diagnostic': None,
    }

    if not same:
        trusted = mp.parent / data.get('trusted_copy', '')

        if trusted.is_file():
            out['diagnostic'] = diagnose.diagnose(
                str(trusted),
                distributed_path,
                {}
            )

    return out


def finding_from_verify(v):
    if v['result'] == 'DISTRIBUTED_MATCHES_TRUSTED':
        return Finding(
            id='B-TMP',
            module='build',
            category='NO_KNOWN_ISSUES',
            severity='INFO',
            confidence='HIGH',
            subject={'artifact': v['artifact_name']},
            title='Distributed file matches the trusted build hash',
            evidence=[
                Evidence(
                    type='hash_pair',
                    rule_id='DISTRIBUTED_MATCHES_TRUSTED',
                    data=v
                )
            ]
        )

    return Finding(
        id='B-TMP',
        module='build',
        category='BUILD_MISMATCH',
        severity='HIGH',
        confidence='HIGH',
        subject={
            'artifact': v['artifact_name'],
            'subtype': 'POST_BUILD_DIFF'
        },
        title='Distributed file differs from the trusted build (cause not determined)',
        evidence=[
            Evidence(
                type='hash_pair',
                rule_id='POST_BUILD_DIFF',
                data=v
            )
        ]
    )
