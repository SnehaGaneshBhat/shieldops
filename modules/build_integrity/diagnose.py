from collections import Counter

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


BENIGN_SECTIONS = {'.note.gnu.build-id'}
MAX_OFFSETS = 200000


def _sections(path):
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)

            return [
                (s.name, s['sh_offset'], s['sh_size'])
                for s in elf.iter_sections()
                if s['sh_type'] != 'SHT_NOBITS' and s['sh_size'] > 0
            ]

    except (ELFError, OSError):
        return None


def _section_of(sections, offset):
    if sections is None:
        return '(not an ELF file)'

    for name, off, size in sections:
        if off <= offset < off + size:
            return name

    return '(headers or padding)'


def diagnose(path_a: str, path_b: str, env: dict | None = None) -> dict:
    env = env or {}

    with open(path_a, 'rb') as f:
        da = f.read()

    with open(path_b, 'rb') as f:
        db = f.read()

    n = min(len(da), len(db))
    offsets = []

    for i in range(n):
        if da[i] != db[i]:
            offsets.append(i)

            if len(offsets) >= MAX_OFFSETS:
                break

    secs = _sections(path_a)

    where = Counter(_section_of(secs, o) for o in offsets)

    first = offsets[0] if offsets else (
        n if len(da) != len(db) else None
    )

    hints = []

    if len(da) != len(db):
        hints.append(
            'File sizes differ: look for embedded paths or a non pinned toolchain.'
        )

    if '.note.gnu.build-id' in where:
        hints.append(
            'The build-id differs: add -Wl,--build-id=none to the link flags.'
        )

    if 'SOURCE_DATE_EPOCH' not in env:
        hints.append('SOURCE_DATE_EPOCH is not set in the recipe.')

    hints.append(
        'The two builds differ. Common causes are timestamps, '
        'embedded paths or non-pinned toolchains. Investigate.'
    )

    benign = (
        bool(offsets)
        and len(da) == len(db)
        and set(where) <= BENIGN_SECTIONS
    )

    return {
        'identical': da == db,
        'size_a': len(da),
        'size_b': len(db),
        'differing_bytes': len(offsets) + abs(len(da) - len(db)),
        'first_diff_offset': first,
        'first_diff_section': (
            _section_of(secs, first) if first is not None else None
        ),
        'sections_with_diffs': dict(where),
        'hints': hints,
        'benign': benign,
    }
