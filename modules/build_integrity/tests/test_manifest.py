from modules.build_integrity import manifest
from modules.build_integrity.hashing import sha256_file
from modules.build_integrity.rebuild import BuildOutcome
from modules.build_integrity.recipe import Recipe


def _release(tmp_path):
    art = tmp_path / 'built_app'
    art.write_bytes(b'ABCDEFGH' * 100)

    recipe = Recipe(
        image='gcc@sha256:x',
        workdir='/src',
        commands=['true'],
        artifact='/out/app',
        env={},
        version_commands=[],
        raw_sha256='r',
        pinned=True,
        path=''
    )

    o = BuildOutcome(
        True,
        str(art),
        sha256_file(str(art)),
        art.stat().st_size
    )

    return manifest.write_manifest(str(tmp_path), recipe, o, 'abc123'), art


def test_untouched_copy_matches(tmp_path):
    mpath, art = _release(tmp_path)
    v = manifest.verify_artifact(mpath, str(art))
    assert v['result'] == 'DISTRIBUTED_MATCHES_TRUSTED'
    assert manifest.finding_from_verify(v).category == 'NO_KNOWN_ISSUES'


def test_one_byte_flip_is_post_build_diff(tmp_path):
    mpath, art = _release(tmp_path)
    data = bytearray(art.read_bytes())
    data[10] ^= 0x01

    tampered = tmp_path / 'tampered'
    tampered.write_bytes(bytes(data))

    v = manifest.verify_artifact(mpath, str(tampered))
    assert v['result'] == 'DISTRIBUTED_DIFFERS_FROM_TRUSTED'
    assert v['diagnostic']['differing_bytes'] == 1 and v['diagnostic']['first_diff_offset'] == 10

    f = manifest.finding_from_verify(v)
    assert f.category == 'BUILD_MISMATCH' and f.subject['subtype'] == 'POST_BUILD_DIFF'
    assert f.confidence == 'HIGH'
