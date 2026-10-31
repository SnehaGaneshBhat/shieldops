import os

import pytest

from modules.build_integrity import runner


pytestmark = pytest.mark.docker

IMAGE = os.environ.get('BUILDGUARD_TEST_IMAGE', 'gcc:13')

CLEAN = '#include <stdio.h>\nint main(void){puts("ok");return 0;}\n'

STAMPED = '#include <stdio.h>\nint main(void){puts(__DATE__ " " __TIME__);return 0;}\n'

FLAGS = (
    'gcc -O2 -g0 -ffile-prefix-map=/src=. -frandom-seed=bg '
    '-Wl,--build-id=none -o /out/app src/main.c'
)


def _project(tmp_path, source, commands, env):
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src' / 'main.c').write_text(source)

    lines = [
        'version: 1',
        'build:',
        f'  image: {IMAGE}',
        '  commands:'
    ]

    lines += [f'    - {c}' for c in commands]
    lines += ['  artifact: /out/app', '  env:']
    lines += [f'    {k}: {v}' for k, v in env.items()]

    (tmp_path / 'buildguard.yml').write_text('\n'.join(lines) + '\n')
    return str(tmp_path)


def test_reproducible_c_matches(tmp_path):
    p = _project(
        tmp_path,
        CLEAN,
        [FLAGS],
        {'SOURCE_DATE_EPOCH': '1700000000', 'TZ': 'UTC'}
    )

    res = runner.run(p, {'allow_unpinned': True})
    assert res.status == 'ok', res.errors
    assert [f.category for f in res.findings] == ['NO_KNOWN_ISSUES']


def test_timestamp_macro_causes_a_mismatch(tmp_path):
    p = _project(
        tmp_path,
        STAMPED,
        ['sleep 2', 'gcc -O2 -o /out/app src/main.c'],
        {'TZ': 'UTC'}
    )

    res = runner.run(p, {'allow_unpinned': True})
    assert res.status == 'ok', res.errors

    f = res.findings[0]
    assert f.category == 'BUILD_MISMATCH'
    assert f.evidence[0].data['diagnostic']['timestamp_macros_in_source'] is True
