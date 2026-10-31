from modules.build_integrity import diagnose
from modules.build_integrity.hashing import sha256_file


def _pair(tmp_path, a: bytes, b: bytes):
    pa, pb = tmp_path / 'a.bin', tmp_path / 'b.bin'
    pa.write_bytes(a)
    pb.write_bytes(b)
    return str(pa), str(pb)


def test_sha256_known_value(tmp_path):
    pa, _ = _pair(tmp_path, b'abc', b'abc')
    assert sha256_file(pa) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


def test_identical_files(tmp_path):
    d = diagnose.diagnose(*_pair(tmp_path, b'same', b'same'))
    assert d['identical'] and d['differing_bytes'] == 0


def test_one_byte_flip(tmp_path):
    d = diagnose.diagnose(*_pair(tmp_path, b'hello world', b'hello_world'))
    assert d['differing_bytes'] == 1 and d['first_diff_offset'] == 5


def test_size_difference_is_hinted(tmp_path):
    d = diagnose.diagnose(*_pair(tmp_path, b'abc', b'abcd'))
    assert 'File sizes differ' in ' '.join(d['hints'])
