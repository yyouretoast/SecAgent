from __future__ import annotations

import importlib.util
import json
import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

import secagent.generator.cache as cache_module
from secagent.cli import app
from secagent.generator import GeneratedScenario, ToolMetadata
from secagent.generator.cache import (
    GENERATOR_SCHEMA_VERSION,
    AgentFingerprintError,
    ScenarioCache,
    agent_source_fingerprint,
)


def _key(cache, *, seed=42, tools=None, overrides=None, settings=None, source="source-a"):
    return cache.key(
        tools=tools or [ToolMetadata("lookup", parameters={"query": "str"})],
        policy_overrides=overrides or {},
        seed=seed,
        settings=settings or {"mode": "per_tool", "scenarios_per_tool": 2},
        source_fingerprint=source,
    )


def test_cache_key_tracks_seed_schema_policy_settings_and_source(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    baseline = _key(cache)
    assert _key(cache, seed=43) != baseline
    assert _key(cache, tools=[ToolMetadata("lookup", parameters={"query": "int"})]) != baseline
    assert _key(cache, overrides={"lookup": "admin"}) != baseline
    assert _key(cache, settings={"mode": "per_tool", "scenarios_per_tool": 3}) != baseline
    assert _key(cache, source="source-b") != baseline


def test_cache_key_distinguishes_generation_modes(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    whole_suite = _key(cache, settings={"mode": "whole_suite", "scenarios_per_tool": 2})
    per_tool = _key(cache, settings={"mode": "per_tool", "scenarios_per_tool": 2})
    assert whole_suite != per_tool


def test_cache_key_preserves_tool_order(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    tools = [
        ToolMetadata("lookup", parameters={"query": "str"}),
        ToolMetadata("update", parameters={"value": "str"}),
    ]
    assert _key(cache, tools=tools) != _key(cache, tools=list(reversed(tools)))


def test_source_fingerprint_tracks_package_python_changes(tmp_path: Path):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "agent.py"
    source.write_text("VALUE = 1", encoding="utf-8")
    module = types.SimpleNamespace(__file__=str(source), __package__="agentpkg")
    initial = agent_source_fingerprint(module)
    source.write_text("VALUE = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) != initial


def test_source_fingerprint_tracks_entrypoint_package_initializer(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    package.mkdir()
    initializer = package / "__init__.py"
    initializer.write_text("VALUE = 1\n", encoding="utf-8")
    source = package / "agent.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)

    initial = agent_source_fingerprint(module)
    initializer.write_text("VALUE = 2\n", encoding="utf-8")
    assert agent_source_fingerprint(module) != initial


@pytest.mark.parametrize("initializer", ["agentpkg/__init__.py", "agentpkg/subpkg/__init__.py"])
def test_source_fingerprint_tracks_nested_entrypoint_package_initializers(
    tmp_path: Path, monkeypatch, initializer: str
):
    package = tmp_path / "agentpkg" / "subpkg"
    package.mkdir(parents=True)
    (tmp_path / "agentpkg" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    source = package / "agent.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch, "agentpkg.subpkg.agent")

    initial = agent_source_fingerprint(module)
    (tmp_path / initializer).write_text("VALUE = 2\n", encoding="utf-8")
    assert agent_source_fingerprint(module) != initial


def test_source_fingerprint_traverses_initializer_imports_but_ignores_unrelated_packages(
    tmp_path: Path, monkeypatch
):
    package = tmp_path / "agentpkg" / "subpkg"
    package.mkdir(parents=True)
    (tmp_path / "agentpkg" / "__init__.py").write_text("import init_helper\n", encoding="utf-8")
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package / "agent.py").write_text("VALUE = 1\n", encoding="utf-8")
    helper = tmp_path / "init_helper.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    unrelated_init = unrelated / "__init__.py"
    unrelated_init.write_text("VALUE = 1\n", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch, "agentpkg.subpkg.agent")

    initial = agent_source_fingerprint(module)
    unrelated_init.write_text("VALUE = 2\n", encoding="utf-8")
    assert agent_source_fingerprint(module) == initial
    helper.write_text("VALUE = 2\n", encoding="utf-8")
    assert agent_source_fingerprint(module) != initial


def test_source_fingerprint_standalone_module_does_not_include_sibling_initializer(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    source = tmp_path / "agent.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    module = types.SimpleNamespace(__file__=str(source), __package__="", __name__="agent")

    initial = agent_source_fingerprint(module)
    (tmp_path / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert agent_source_fingerprint(module) == initial


def _fingerprint_module(root: Path, monkeypatch, name: str = "agentpkg.agent"):
    monkeypatch.chdir(root)
    source = root.joinpath(*name.split(".")).with_suffix(".py")
    package_parts = name.split(".")[:-1]
    package = ".".join(package_parts)
    return types.SimpleNamespace(__file__=str(source), __package__=package, __name__=name)


def test_source_fingerprint_tracks_direct_and_transitive_external_helpers(
    tmp_path: Path, monkeypatch
):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text(
        "from helpers import direct\nVALUE = direct.VALUE", encoding="utf-8"
    )
    (tmp_path / "helpers.py").write_text("from deeper import VALUE", encoding="utf-8")
    (tmp_path / "deeper.py").write_text("VALUE = 1", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    initial = agent_source_fingerprint(module)
    (tmp_path / "helpers.py").write_text("from deeper import VALUE\nDIRECT = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) != initial
    direct_changed = agent_source_fingerprint(module)
    (tmp_path / "deeper.py").write_text("VALUE = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) != direct_changed


def test_source_fingerprint_ignores_unimported_sources_and_external_dependencies(
    tmp_path: Path, monkeypatch
):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "agent.py"
    source.write_text("import json\nimport pytest\nVALUE = json.dumps(1)", encoding="utf-8")
    (package / "unused.py").write_text("VALUE = 1", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    initial = agent_source_fingerprint(module)
    (package / "unused.py").write_text("VALUE = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) == initial
    assert importlib.util.find_spec("pytest") is not None


def test_source_fingerprint_excludes_known_standard_and_installed_dependencies(
    tmp_path: Path, monkeypatch
):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text("import json\nimport pytest", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    external_sources = {
        Path(importlib.util.find_spec("json").origin).resolve(),
        Path(importlib.util.find_spec("pytest").origin).resolve(),
    }
    original = Path.read_bytes
    reads: list[Path] = []

    def track_reads(path):
        resolved = path.resolve()
        reads.append(resolved)
        assert resolved not in external_sources
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", track_reads)
    agent_source_fingerprint(module)
    assert external_sources.isdisjoint(reads)


def test_source_fingerprint_recognizes_user_site_packages_dependency(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text("import user_site_dep", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)

    user_site = tmp_path / "user" / "site-packages"
    dependency = user_site / "user_site_dep" / "__init__.py"
    dependency.parent.mkdir(parents=True)
    dependency.write_text("VALUE = 1", encoding="utf-8")
    monkeypatch.setattr(cache_module.site, "getsitepackages", lambda: [])
    monkeypatch.setattr(cache_module.site, "getusersitepackages", lambda: str(user_site))
    monkeypatch.setattr(
        cache_module.sysconfig,
        "get_paths",
        lambda: {
            "stdlib": str(tmp_path / "stdlib"),
            "platstdlib": str(tmp_path / "stdlib"),
            "purelib": str(tmp_path / "other" / "purelib"),
            "platlib": str(tmp_path / "other" / "platlib"),
        },
    )
    original = cache_module.importlib.machinery.PathFinder.find_spec

    # Return an explicit package spec whose source sits in the controlled user site.
    def find_user_site_spec(name, path=None, target=None):
        if name == "user_site_dep":
            spec = importlib.machinery.ModuleSpec(name, loader=None, is_package=True)
            spec.origin = str(dependency)
            spec.submodule_search_locations = [str(dependency.parent)]
            return spec
        return original(name, path, target)

    monkeypatch.setattr(
        cache_module.importlib.machinery.PathFinder, "find_spec", find_user_site_spec
    )
    assert agent_source_fingerprint(module)


@pytest.mark.parametrize("reserved", ["json", "secagent"])
def test_source_fingerprint_prefers_local_sources_with_reserved_names(
    tmp_path: Path, monkeypatch, reserved: str
):
    if reserved == "json":
        target = tmp_path / "json.py"
        target.write_text("VALUE = 1", encoding="utf-8")
        import_line = "import json"
    else:
        secagent = tmp_path / "secagent"
        secagent.mkdir()
        (secagent / "__init__.py").write_text("", encoding="utf-8")
        target = secagent / "helper.py"
        target.write_text("VALUE = 1", encoding="utf-8")
        import_line = "import secagent.helper"
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text(import_line, encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    initial = agent_source_fingerprint(module)
    target.write_text("VALUE = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) != initial


def test_source_fingerprint_fails_for_unresolved_import(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text("import missing_local_dependency_xyz", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    with pytest.raises(AgentFingerprintError, match="Cannot classify import"):
        agent_source_fingerprint(module)


def test_source_fingerprint_fails_for_ambiguous_local_import(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text("import helper", encoding="utf-8")
    (package / "helper.py").write_text("VALUE = 1", encoding="utf-8")
    (tmp_path / "helper.py").write_text("VALUE = 2", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    with pytest.raises(AgentFingerprintError, match="Ambiguous local import"):
        agent_source_fingerprint(module)


def test_source_fingerprint_resolves_relative_and_from_package_imports(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    (package / "sub").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text(
        "from . import sub\nfrom .sub import helper", encoding="utf-8"
    )
    (package / "sub" / "__init__.py").write_text("", encoding="utf-8")
    helper = package / "sub" / "helper.py"
    helper.write_text("VALUE = 1", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    first = agent_source_fingerprint(module)
    helper.write_text("VALUE = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) != first


def test_source_fingerprint_does_not_treat_module_attribute_as_submodule(
    tmp_path: Path, monkeypatch
):
    package = tmp_path / "package"
    (package / "module").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "module.py").write_text("symbol = 1", encoding="utf-8")
    symbol_module = package / "module" / "symbol.py"
    symbol_module.write_text("VALUE = 1", encoding="utf-8")
    (package / "agent.py").write_text(
        "from package.module import symbol\nVALUE = symbol", encoding="utf-8"
    )
    module = _fingerprint_module(tmp_path, monkeypatch, "package.agent")
    initial = agent_source_fingerprint(module)
    symbol_module.write_text("VALUE = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) == initial


def test_source_fingerprint_tracks_genuine_package_submodule(tmp_path: Path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text("from package import submodule", encoding="utf-8")
    submodule = package / "submodule.py"
    submodule.write_text("VALUE = 1", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch, "package.agent")
    initial = agent_source_fingerprint(module)
    submodule.write_text("VALUE = 2", encoding="utf-8")
    assert agent_source_fingerprint(module) != initial


def test_source_fingerprint_handles_cycles_and_is_deterministic(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text("import helper", encoding="utf-8")
    (package / "helper.py").write_text("import agent\nVALUE = 1", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    fingerprints = [agent_source_fingerprint(module) for _ in range(3)]
    assert fingerprints[0] == fingerprints[1] == fingerprints[2]


def test_source_fingerprint_fails_for_unreadable_relevant_source(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    helper = package / "helper.py"
    helper.write_text("VALUE = 1", encoding="utf-8")
    (package / "agent.py").write_text("import helper", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    original = Path.read_bytes

    def unreadable(path):
        if path == helper:
            raise PermissionError("denied")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    with pytest.raises(AgentFingerprintError, match="Cannot read relevant agent source"):
        agent_source_fingerprint(module)


def test_source_fingerprint_fails_for_unparsable_relevant_source(tmp_path: Path, monkeypatch):
    package = tmp_path / "agentpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text("import helper", encoding="utf-8")
    (package / "helper.py").write_text("def broken(:\n", encoding="utf-8")
    module = _fingerprint_module(tmp_path, monkeypatch)
    with pytest.raises(AgentFingerprintError, match="Cannot parse relevant agent source"):
        agent_source_fingerprint(module)


def test_source_fingerprint_rejects_entrypoint_without_source():
    with pytest.raises(AgentFingerprintError, match="no usable source file"):
        agent_source_fingerprint(types.SimpleNamespace(__package__="agentpkg"))


@pytest.mark.parametrize("command", ["generate", "scan"])
def test_cli_fingerprint_errors_exit_before_cache_key_creation(
    tmp_path: Path, monkeypatch, command: str
):
    import secagent.cli as cli

    cache_calls = []
    monkeypatch.setattr(
        cache_module.ScenarioCache,
        "load",
        lambda *args, **kwargs: cache_calls.append("load"),
    )
    monkeypatch.setattr(
        cache_module.ScenarioCache,
        "save",
        lambda *args, **kwargs: cache_calls.append("save"),
    )

    no_source = types.SimpleNamespace(__package__="agentpkg")
    monkeypatch.setattr(
        cli,
        "_resolve_agent_target",
        lambda *args, **kwargs: (None, no_source, [ToolMetadata("lookup")]),
    )
    args = [command, "--agent", "fixture:app"]
    if command == "generate":
        args.extend(["--output-dir", str(tmp_path / "generated")])
    else:
        args.extend(
            [
                "--output-report",
                str(tmp_path / "report.json"),
                "--output-markdown",
                str(tmp_path / "report.md"),
            ]
        )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    assert "Error fingerprinting agent source" in result.stdout
    assert cache_calls == []


def test_cache_roundtrip_detects_corrupted_and_incomplete_entries(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    key = _key(cache)
    data = [GeneratedScenario("GEN-001", "ASI01", "Title", "Desc", "lookup", "prompt").to_dict()]
    cache.save(key, data)
    assert cache.load(key) == data
    entry = tmp_path / f".scenario-cache-{key}.json"
    entry.write_text("{broken", encoding="utf-8")
    assert cache.load(key) is None
    entry.write_text(json.dumps({"key": key, "scenarios": []}), encoding="utf-8")
    assert cache.load(key) is None


def _write_cache_records(tmp_path: Path, key: str, records: list[dict], **overrides) -> Path:
    document = {
        "cache_schema_version": cache_module.CACHE_SCHEMA_VERSION,
        "generator_schema_version": GENERATOR_SCHEMA_VERSION,
        "key": key,
        "scenarios": records,
        # Deliberately calculate the checksum after constructing even malformed records.
        "scenarios_sha256": cache_module._digest(records),
        **overrides,
    }
    path = tmp_path / f".scenario-cache-{key}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _valid_record() -> dict:
    return GeneratedScenario("GEN-001", "ASI01", "Title", "Desc", "lookup", "prompt").to_dict()


def test_cache_rejects_scenario_missing_required_field_with_valid_checksum(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    key = _key(cache)
    record = _valid_record()
    del record["title"]
    _write_cache_records(tmp_path, key, [record])
    assert cache.load(key) is None


def test_cache_rejects_incorrect_required_field_type_with_valid_checksum(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    key = _key(cache)
    record = _valid_record()
    record["description"] = 17
    _write_cache_records(tmp_path, key, [record])
    assert cache.load(key) is None


def test_cache_rejects_incorrect_defaulted_field_types_with_valid_checksum(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    key = _key(cache)
    for field, value in (("injected_parameters", []), ("caller_role", 2), ("approval_granted", 1)):
        record = _valid_record()
        record[field] = value
        _write_cache_records(tmp_path, key, [record])
        assert cache.load(key) is None


def test_cache_rejects_invalid_and_duplicate_ids_with_valid_checksums(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    key = _key(cache)
    for invalid_id in ("", "  ", "../GEN-002", "GEN/002"):
        record = _valid_record()
        record["id"] = invalid_id
        _write_cache_records(tmp_path, key, [record])
        assert cache.load(key) is None
    record = _valid_record()
    duplicate = {**record}
    _write_cache_records(tmp_path, key, [record, duplicate])
    assert cache.load(key) is None


def test_cache_rejects_unsupported_cache_and_generator_versions(tmp_path: Path):
    cache = ScenarioCache(tmp_path)
    key = _key(cache)
    for field, version in (("cache_schema_version", 999), ("generator_schema_version", 999)):
        _write_cache_records(tmp_path, key, [_valid_record()], **{field: version})
        assert cache.load(key) is None


def test_cache_accepts_empty_suite_and_absent_defaulted_fields(tmp_path: Path):
    """Empty suites are valid: ScenarioGenerator.generate([]) returns an empty list."""
    cache = ScenarioCache(tmp_path)
    key = _key(cache)
    _write_cache_records(tmp_path, key, [])
    assert cache.load(key) == []
    record = _valid_record()
    del record["injected_parameters"]
    del record["caller_role"]
    del record["approval_granted"]
    del record["expected_failure_policy"]
    _write_cache_records(tmp_path, key, [record])
    assert cache.load(key) == [record]


def test_generate_replays_cache_and_rewrites_stale_manifests(tmp_path: Path, monkeypatch):
    import secagent.cli as cli
    import secagent.generator.cache as cache_module

    output = tmp_path / "generated"
    calls = []

    def synth(*args, **kwargs):
        calls.append(1)
        return [
            GeneratedScenario("GEN-ASI01-001", "ASI01-AgentGoalHijack", "T", "D", "lookup", "P")
        ]

    monkeypatch.setattr(cli, "_synthesize_whole_suite_scenarios", synth)
    monkeypatch.setattr(cli, "_synthesize_per_tool_scenarios", synth)
    cache_type = cache_module.ScenarioCache

    class IsolatedCache(cache_type):
        def __init__(self, directory):
            super().__init__(tmp_path / "cache")

    monkeypatch.setattr(cache_module, "ScenarioCache", IsolatedCache)
    runner = CliRunner()
    args = ["generate", "--agent", "examples.devops_agent.agent", "--output-dir", str(output)]
    assert runner.invoke(app, args).exit_code == 0
    assert runner.invoke(app, args).exit_code == 0
    assert len(calls) == 1
    assert (output / "generated_scenarios.json").is_file()
    previous = json.loads((output / "generated_scenarios.json").read_text(encoding="utf-8"))
    previous.append({"id": "GEN-OLD-999"})
    (output / "generated_scenarios.json").write_text(json.dumps(previous), encoding="utf-8")
    (output / "GEN-OLD-999.json").write_text("{}", encoding="utf-8")
    (output / "GEN-USER-001.json").write_text("{}", encoding="utf-8")
    assert runner.invoke(app, [*args, "--per-tool", "3"]).exit_code == 0
    assert not (output / "GEN-OLD-999.json").exists()
    assert (output / "GEN-USER-001.json").exists()
    assert len(calls) == 2


def test_default_generate_and_scan_share_whole_suite_cache(tmp_path: Path, monkeypatch):
    import secagent.cli as cli
    import secagent.generator.cache as cache_module

    shared_cache = tmp_path / "cache"
    output = tmp_path / "generated"
    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(
        "version: '1.0'\ntool_tier_overrides: {}\npolicies:\n"
        "  - id: POL-ASI08-001\n"
        "    name: Minimal circuit breaker policy\n"
        "    owasp_category: 'ASI08: Cascading Failures'\n"
        "    severity: HIGH\n"
        "    rule_type: circuit_breaker\n"
        "    condition:\n"
        "      max_total_steps: 10\n"
        "      max_consecutive_identical_tools: 3\n"
        "    failure_action: WARN\n",
        encoding="utf-8",
    )
    tool = ToolMetadata("lookup", parameters={"query": "str"})
    monkeypatch.setattr(cli, "_resolve_agent_target", lambda *args, **kwargs: (None, None, [tool]))
    monkeypatch.setattr(cli, "_execute_scenarios_with_telemetry", lambda *args, **kwargs: [])

    cache_type = cache_module.ScenarioCache

    class SharedCache(cache_type):
        def __init__(self, directory):
            super().__init__(shared_cache)

    monkeypatch.setattr(cache_module, "ScenarioCache", SharedCache)
    calls = []
    original_synthesis = cli._synthesize_whole_suite_scenarios

    def synthesize(*args, **kwargs):
        calls.append(1)
        return original_synthesis(*args, **kwargs)

    monkeypatch.setattr(cli, "_synthesize_whole_suite_scenarios", synthesize)
    runner = CliRunner()
    generated = runner.invoke(
        app,
        ["generate", "--output-dir", str(output), "--policies", str(policy_file)],
    )
    assert generated.exit_code == 0, generated.stdout
    generated_records = json.loads(
        (output / "generated_scenarios.json").read_text(encoding="utf-8")
    )

    scan_records = []
    monkeypatch.setattr(
        cli,
        "_execute_scenarios_with_telemetry",
        lambda target, mod, tools, records, overrides, **kwargs: scan_records.extend(records) or [],
    )
    scanned = runner.invoke(
        app,
        [
            "scan",
            "--policies",
            str(policy_file),
            "--output-report",
            str(tmp_path / "report.json"),
            "--output-markdown",
            str(tmp_path / "report.md"),
        ],
    )
    assert scanned.exit_code == 0, scanned.stdout
    assert scan_records == generated_records
    assert len(calls) == 1


def test_whole_suite_scan_includes_suite_level_recursion(tmp_path: Path, monkeypatch):
    import secagent.cli as cli
    import secagent.generator.cache as cache_module

    tool = ToolMetadata("lookup", parameters={"query": "str"})
    monkeypatch.setattr(cli, "_resolve_agent_target", lambda *args, **kwargs: (None, None, [tool]))
    cache_type = cache_module.ScenarioCache

    class IsolatedCache(cache_type):
        def __init__(self, directory):
            super().__init__(tmp_path / "cache")

    monkeypatch.setattr(cache_module, "ScenarioCache", IsolatedCache)
    records = []
    synthesis_calls = []
    original_synthesis = cli._synthesize_whole_suite_scenarios

    def synthesize(*args, **kwargs):
        synthesis_calls.append(1)
        return original_synthesis(*args, **kwargs)

    monkeypatch.setattr(cli, "_synthesize_whole_suite_scenarios", synthesize)
    monkeypatch.setattr(
        cli,
        "_execute_scenarios_with_telemetry",
        lambda target, mod, tools, scenarios, overrides, **kwargs: records.extend(scenarios) or [],
    )
    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(
        "version: '1.0'\ntool_tier_overrides: {}\npolicies:\n"
        "  - id: POL-ASI08-001\n"
        "    name: Minimal circuit breaker policy\n"
        "    owasp_category: 'ASI08: Cascading Failures'\n"
        "    severity: HIGH\n"
        "    rule_type: circuit_breaker\n"
        "    condition:\n"
        "      max_total_steps: 10\n"
        "      max_consecutive_identical_tools: 3\n"
        "    failure_action: WARN\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--policies",
            str(policy_file),
            "--output-report",
            str(tmp_path / "report.json"),
            "--output-markdown",
            str(tmp_path / "report.md"),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert len(synthesis_calls) == 1
    recursion = [item for item in records if item["owasp_category"] == "ASI08-CascadingFailures"]
    assert len(recursion) == 1
    assert recursion[0]["target_tool"] == "system"
