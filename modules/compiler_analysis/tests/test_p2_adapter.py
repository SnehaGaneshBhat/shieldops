from types import SimpleNamespace

import pytest

from modules.compiler_analysis import lab_adapter


class FakeRunner:
    def __init__(self, result=None, image=True):
        self.result = result or SimpleNamespace(
            returncode=0, stdout="lab_run complete", stderr="", timed_out=False, error=None
        )
        self.image = image
        self.calls = []

    def docker_available(self):
        return True

    def image_present(self, image):
        self.calls.append(("image_present", image))
        return self.image

    def run_container(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result


def test_adapter_uses_p2_readiness_and_image_checks(monkeypatch):
    runner = FakeRunner(image=False)
    monkeypatch.setattr(lab_adapter, "dr", runner)
    result = lab_adapter.check()
    assert result[0] == "TOOL_MISSING"
    assert runner.calls == [("image_present", lab_adapter.IMAGE)]


def test_adapter_uses_shared_runner_contract(tmp_path, monkeypatch):
    runner = FakeRunner()
    monkeypatch.setattr(lab_adapter, "dr", runner)
    output = lab_adapter.run_lab(tmp_path, tmp_path / "out", project_cc="clang",
                                 opt_level="-O2", strip=True, timeout=90, scan_id="scan-123")
    args, kwargs = runner.calls[0]
    assert output == "lab_run complete"
    assert args[0] == lab_adapter.IMAGE
    assert kwargs["network_none"] is True and kwargs["timeout"] == 90
    assert kwargs["scan_id"] == "scan-123"
    assert kwargs["env"]["BG_OPT"] == "-O2" and kwargs["env"]["BG_STRIP"] == "1"


def test_adapter_preserves_runner_timeout_error(tmp_path, monkeypatch):
    timeout = SimpleNamespace(returncode=-1, stdout="", stderr="timeout", timed_out=True, error="TIMEOUT")
    monkeypatch.setattr(lab_adapter, "dr", FakeRunner(result=timeout))
    with pytest.raises(lab_adapter.LabError) as caught:
        lab_adapter.run_lab(tmp_path, tmp_path / "out", timeout=17)
    assert caught.value.code == "TIMEOUT"
