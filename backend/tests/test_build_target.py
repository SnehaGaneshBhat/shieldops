"""Focused tests for Build Integrity target and recipe resolution in backend/orchestrator.py.

Verifies:
1. Workspace root contains buildguard.yml -> workspace root selected.
2. Explicit compiler sample contains buildguard.yml -> sample selected.
3. Explicit build sample contains buildguard.yml -> sample selected.
4. External project has no recipe -> original project root retained.
5. Sample path escaping the workspace -> rejected, original project root retained.
6. Sample does not contain the recipe -> original project root retained.
7. End-to-end _call_module('build', ...) passes the resolved target to runner.
"""

from pathlib import Path
import pytest

from backend.orchestrator import _resolve_build_target, _call_module, REPO_ROOT


def test_workspace_root_contains_recipe_selects_root(tmp_path):
    """When workspace root contains configured recipe, workspace root is selected."""
    ws = tmp_path / "project_with_recipe"
    ws.mkdir()
    (ws / "buildguard.yml").write_text("version: 1\n", encoding="utf-8")

    # Even if compiler_sample with another recipe is present, root takes precedence
    sample_dir = ws / "sub_sample"
    sample_dir.mkdir()
    (sample_dir / "buildguard.yml").write_text("version: 1\n", encoding="utf-8")

    options = {
        "recipe_path": "buildguard.yml",
        "compiler_sample": "sub_sample",
    }
    resolved = _resolve_build_target(options, str(ws))
    assert resolved == str(ws.resolve())


def test_explicit_compiler_sample_contains_recipe_selects_sample(tmp_path):
    """When root lacks recipe but explicit compiler_sample has it, sample is selected."""
    ws = tmp_path / "project_no_root_recipe"
    ws.mkdir()

    sample_dir = ws / "test_samples" / "compiler_hello"
    sample_dir.mkdir(parents=True)
    (sample_dir / "buildguard.yml").write_text("version: 1\n", encoding="utf-8")

    options = {
        "recipe_path": "buildguard.yml",
        "compiler_sample": "test_samples/compiler_hello",
    }
    resolved = _resolve_build_target(options, str(ws))
    assert resolved == str(sample_dir.resolve())


def test_explicit_build_sample_contains_recipe_selects_sample(tmp_path):
    """When root lacks recipe but explicit build_sample has it, sample is selected."""
    ws = tmp_path / "project_custom_build"
    ws.mkdir()

    sample_dir = ws / "build_pkg"
    sample_dir.mkdir()
    (sample_dir / "buildguard.yml").write_text("version: 1\n", encoding="utf-8")

    options = {
        "recipe_path": "buildguard.yml",
        "build_sample": "build_pkg",
    }
    resolved = _resolve_build_target(options, str(ws))
    assert resolved == str(sample_dir.resolve())


def test_external_project_no_recipe_retains_root(tmp_path):
    """External project without recipe never substitutes bundled sample; retains project root."""
    external_ws = tmp_path / "external_user_project"
    external_ws.mkdir()

    # Case A: no sample passed
    resolved_none = _resolve_build_target({}, str(external_ws))
    assert resolved_none == str(external_ws.resolve())

    # Case B: default extension setting pointing to test_samples/compiler_hello
    # Because external_ws is outside REPO_ROOT and has no such subfolder, it must NOT substitute bundled sample!
    options = {
        "compiler_sample": "test_samples/compiler_hello",
        "recipe_path": "buildguard.yml",
    }
    resolved_ext = _resolve_build_target(options, str(external_ws))
    assert resolved_ext == str(external_ws.resolve())


def test_sample_path_escaping_workspace_is_rejected(tmp_path):
    """Sample path traversal attempting to escape project workspace is rejected."""
    ws = tmp_path / "project"
    ws.mkdir()

    options = {
        "compiler_sample": "../../outside_sample",
        "build_sample": "../other_sample",
        "recipe_path": "buildguard.yml",
    }
    resolved = _resolve_build_target(options, str(ws))
    assert resolved == str(ws.resolve())


def test_sample_does_not_contain_recipe_retains_root(tmp_path):
    """When sample directory exists but does not contain the recipe, retain project root."""
    ws = tmp_path / "project"
    ws.mkdir()

    sample_no_recipe = ws / "sample_empty"
    sample_no_recipe.mkdir()

    options = {
        "compiler_sample": "sample_empty",
        "recipe_path": "buildguard.yml",
    }
    resolved = _resolve_build_target(options, str(ws))
    assert resolved == str(ws.resolve())


def test_build_call_module_passes_resolved_target_to_runner(tmp_path, monkeypatch):
    """_call_module('build', ...) resolves the target and passes it to mod.run."""
    ws = tmp_path / "project"
    ws.mkdir()

    sample_dir = ws / "sample_c"
    sample_dir.mkdir()
    (sample_dir / "buildguard.yml").write_text("version: 1\n", encoding="utf-8")

    options = {
        "compiler_sample": "sample_c",
        "recipe_path": "buildguard.yml",
    }

    import modules.build_integrity as bi
    recorded_calls = []

    def mock_run(target, opts):
        recorded_calls.append((target, opts))
        from backend.schemas import ModuleResult
        return ModuleResult(
            module="build",
            status="ok",
            findings=[],
            errors=[],
            tool_versions={},
            duration_ms=10,
            checks_performed=["rebuild_comparison"],
        )

    monkeypatch.setattr(bi, "run", mock_run)

    result = _call_module("build", str(ws), options)
    assert len(recorded_calls) == 1
    passed_target, _ = recorded_calls[0]
    assert passed_target == str(sample_dir.resolve())
    assert result.tool_versions.get("target") == str(sample_dir.resolve())
