"""Deterministic scenario cache with AST-based local agent source fingerprinting.

Fingerprinting follows statically resolvable Python imports from the entrypoint
and hashes only reachable source files owned by the declared local roots.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import site
import sys
import sysconfig
import tempfile
from dataclasses import MISSING, fields
from pathlib import Path
from typing import Any

from secagent.generator import GeneratedScenario

CACHE_SCHEMA_VERSION = 1
GENERATOR_SCHEMA_VERSION = 2
DEFAULT_SEED = 42
_SCENARIO_FIELDS = {item.name: item for item in fields(GeneratedScenario)}
_SCENARIO_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class AgentFingerprintError(RuntimeError):
    """Raised when the local agent source closure cannot be fingerprinted safely."""


def _valid_scenario(item: Any) -> bool:
    """Check a cached record against GeneratedScenario's constructor contract."""
    if not isinstance(item, dict):
        return False
    for name, definition in _SCENARIO_FIELDS.items():
        if name not in item:
            if definition.default is MISSING and definition.default_factory is MISSING:
                return False
            continue
        value = item[name]
        expected = definition.type
        if expected is str and type(value) is not str:
            return False
        if expected is bool and type(value) is not bool:
            return False
        if name == "taint_payload" and value is not None and type(value) is not str:
            return False
        if expected == "dict[str, Any]" or getattr(expected, "__origin__", None) is dict:
            if not isinstance(value, dict):
                return False
    scenario_id = item.get("id")
    return isinstance(scenario_id, str) and _SCENARIO_ID.fullmatch(scenario_id) is not None


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def agent_source_fingerprint(module: Any = None) -> str:
    """Hash the entrypoint and its statically imported local Python dependencies.

    Local ownership is limited to the entrypoint package root (or standalone
    module directory) and the current working directory. A unique source under
    either root takes precedence and is fingerprinted, including when its name
    matches a standard-library or SecAgent module. Conflicting local candidates
    fail closed. Otherwise Python's path-based import finders classify the name:
    built-in/frozen modules, sources under the interpreter's stdlib directories,
    installed distributions under site-package directories, and the actual
    SecAgent package are excluded. A missing spec or a spec outside these known
    owners raises AgentFingerprintError; callers can add a legitimate local
    project root explicitly rather than silently widening the scan.

    For ``from X import Y``, X is always resolved. X.Y is considered only when
    X is a local package/namespace package and Python's path finder resolves
    that child. This preserves package submodule imports without mistaking a
    same-named attribute in a regular module for a dependency.
    """
    if module is None:
        # No explicit agent is the existing benchmark/default mode.
        return _digest([])
    module_path = getattr(module, "__file__", None)
    if not module_path:
        raise AgentFingerprintError("Agent entrypoint has no usable source file (__file__)")
    path = Path(module_path).resolve()
    if not path.is_file() or path.suffix != ".py":
        raise AgentFingerprintError(f"Agent entrypoint source is not a Python file: {path}")

    package = getattr(module, "__package__", "") or ""
    package_root = path.parent
    if package:
        # Ascend only through regular package directories; namespace package
        # portions are handled by the cwd root and import resolution below.
        while (package_root.parent / "__init__.py").is_file():
            package_root = package_root.parent
    roots: list[tuple[str, Path]] = [("entry", package_root)]
    cwd = Path.cwd().resolve()
    if cwd not in [root for _, root in roots]:
        roots.append(("cwd", cwd))

    def local_candidates(name: str) -> list[tuple[Path, bool]]:
        parts = name.split(".") if name else []
        if not parts or any(not part.isidentifier() for part in parts):
            return []
        found: set[tuple[Path, bool]] = set()
        for _, root in roots:
            base = root.joinpath(*parts)
            file_candidate = base.with_suffix(".py")
            init_candidate = base / "__init__.py"
            if file_candidate.is_file():
                found.add((file_candidate.resolve(), False))
            if init_candidate.is_file():
                found.add((init_candidate.resolve(), True))
            elif base.is_dir() and not file_candidate.is_file():
                # Namespace package portions have no source file of their own.
                found.add((base.resolve(), True))
        return sorted(found, key=lambda item: (item[0].as_posix(), item[1]))

    configured_paths = sysconfig.get_paths()
    stdlib_roots = {
        Path(value).expanduser().resolve()
        for key, value in configured_paths.items()
        if key in {"stdlib", "platstdlib"} and value
    }
    # Only Python's established installation locations count as third-party.
    # In particular, arbitrary sys.path entries remain unknown and fail closed.
    user_site = site.getusersitepackages()
    user_sites = [user_site] if isinstance(user_site, str) else list(user_site)
    site_roots = {
        Path(value).expanduser().resolve()
        for value in (
            *site.getsitepackages(),
            *user_sites,
            configured_paths.get("purelib"),
            configured_paths.get("platlib"),
        )
        if value
    }
    framework_root = Path(__file__).resolve().parents[1]

    def under(path: Path, directory: Path) -> bool:
        try:
            path.relative_to(directory)
            return True
        except ValueError:
            return False

    def external_spec(name: str):
        """Resolve without importing modules, using path-based finders only."""
        parts = name.split(".")
        search_path: list[str] | None = sys.path
        spec = None
        qualified = ""
        for part in parts:
            qualified = f"{qualified}.{part}" if qualified else part
            try:
                spec = importlib.machinery.PathFinder.find_spec(qualified, search_path)
            except (KeyError, ValueError):
                ns_dirs = [
                    str(Path(base) / part)
                    for base in (search_path or ())
                    if (Path(base) / part).is_dir()
                ]
                if ns_dirs:
                    spec = importlib.machinery.ModuleSpec(qualified, None, is_package=True)
                    spec.submodule_search_locations = ns_dirs
                else:
                    spec = None
            if spec is None and not qualified.partition(".")[2]:
                spec = importlib.machinery.BuiltinImporter.find_spec(qualified)
                if spec is None:
                    spec = importlib.machinery.FrozenImporter.find_spec(qualified)
            if spec is None:
                return None
            locs = spec.submodule_search_locations
            search_path = list(locs) if locs is not None else None
            if qualified != name and search_path is None:
                return None
        return spec

    def resolve_name(name: str) -> tuple[list[tuple[str, Path]], bool, str]:
        """Return local source work, package status, or a known external owner."""
        parts = name.split(".")
        if not name or any(not part.isidentifier() for part in parts):
            raise AgentFingerprintError(f"Cannot resolve imported name '{name}' safely")
        local_work: list[tuple[str, Path]] = []
        for index in range(1, len(parts) + 1):
            prefix = ".".join(parts[:index])
            # Explicit local roots always win, even when an earlier prefix was
            # found in site-packages or the stdlib.
            found = local_candidates(prefix)
            if len(found) > 1:
                raise AgentFingerprintError(
                    f"Ambiguous local import '{prefix}'; declare one unambiguous project root"
                )
            if found:
                source, is_package = found[0]
                if source.name != "__init__.py" and source.is_file():
                    local_work.append((prefix, source))
                if index < len(parts) and not is_package:
                    raise AgentFingerprintError(
                        f"Cannot resolve '{name}': '{prefix}' is a local module, not a package"
                    )
                if index == len(parts):
                    return local_work, is_package, "local"
                continue

            spec = external_spec(prefix)
            if spec is None:
                raise AgentFingerprintError(
                    f"Cannot classify import '{name}': no local source or installed import spec "
                    f"for '{prefix}'. Add the local project directory to the declared roots."
                )
            origin = getattr(spec, "origin", None)
            locations = [Path(item).resolve() for item in (spec.submodule_search_locations or [])]
            if origin and origin not in {"built-in", "frozen", "namespace"}:
                origin_path = Path(origin).resolve()
                if under(origin_path, framework_root):
                    owner = "framework"
                elif any(under(origin_path, base) for base in stdlib_roots):
                    owner = "stdlib"
                elif any(under(origin_path, base) for base in site_roots):
                    owner = "third-party"
                else:
                    raise AgentFingerprintError(
                        f"Cannot classify import '{name}': source '{origin_path}' is outside "
                        "declared local roots and known external locations"
                    )
            elif locations:
                owners = {
                    "local"
                    if any(under(location, root) for _, root in roots)
                    else "stdlib"
                    if any(under(location, base) for base in stdlib_roots)
                    else "third-party"
                    if any(under(location, base) for base in site_roots)
                    else "unknown"
                    for location in locations
                }
                if len(owners) != 1 or "unknown" in owners:
                    raise AgentFingerprintError(
                        f"Cannot classify namespace import '{name}' from locations {locations}"
                    )
                owner = owners.pop()
            else:
                owner = "stdlib" if origin in {"built-in", "frozen"} else "unknown"
                if owner == "unknown":
                    raise AgentFingerprintError(f"Cannot classify import '{name}' safely")
            if index < len(parts) and spec.submodule_search_locations is None:
                raise AgentFingerprintError(f"Cannot resolve '{name}': '{prefix}' is not a package")
            if index == len(parts):
                return local_work, bool(spec.submodule_search_locations), owner
        raise AgentFingerprintError(f"Cannot resolve import '{name}' safely")

    module_name = getattr(module, "__name__", path.stem)
    queue: list[tuple[str, Path]] = []
    # Importing a dotted entrypoint executes each regular package initializer
    # on its package path. Anchor this walk at the entrypoint file so external
    # packages (including SecAgent) are never found by a broad source scan.
    package_parts = package.split(".") if package else []
    package_dir = path.parent
    for index in range(len(package_parts), 0, -1):
        initializer = package_dir / "__init__.py"
        if initializer.is_file():
            queue.append((".".join(package_parts[:index]), initializer))
        package_dir = package_dir.parent
    queue.append((module_name, path))
    visited: set[Path] = set()
    sources: dict[Path, bytes] = {}
    while queue:
        module_name, source = queue.pop(0)
        source = source.resolve()
        if source in visited:
            continue
        visited.add(source)
        try:
            content = source.read_bytes()
        except OSError as exc:
            raise AgentFingerprintError(
                f"Cannot read relevant agent source '{source}': {exc}"
            ) from exc
        sources[source] = content
        try:
            tree = ast.parse(content, filename=str(source))
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise AgentFingerprintError(
                f"Cannot parse relevant agent source '{source}': {exc}"
            ) from exc

        is_package = source.name == "__init__.py"
        current_package = module_name if is_package else module_name.rpartition(".")[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    work, _, owner = resolve_name(alias.name)
                    if owner == "local":
                        queue.extend(work)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    try:
                        base_name = importlib.util.resolve_name(
                            "." * node.level + base, current_package
                        )
                    except (ImportError, ValueError) as exc:
                        raise AgentFingerprintError(
                            f"Cannot resolve relative import in '{source}': {exc}"
                        ) from exc
                elif base:
                    base_name = base
                else:
                    base_name = current_package
                base_work, base_is_package, base_owner = resolve_name(base_name)
                if base_owner == "local":
                    queue.extend(base_work)
                if base_is_package and base_owner == "local":
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        child_name = f"{base_name}.{alias.name}"
                        child_candidates = local_candidates(child_name)
                        if child_candidates:
                            child_work, _, child_owner = resolve_name(child_name)
                            if child_owner == "local":
                                queue.extend(child_work)

    def identity(source: Path) -> str:
        # Prefer the cwd identity for files inside the project; otherwise use
        # the entrypoint root. Root labels prevent collisions between roots.
        for label, root in sorted(roots, key=lambda item: len(item[1].parts), reverse=True):
            try:
                return f"{label}/{source.relative_to(root).as_posix()}"
            except ValueError:
                pass
        raise AgentFingerprintError(f"Relevant source is outside declared local roots: {source}")

    records = [
        (identity(source), hashlib.sha256(content).hexdigest())
        for source, content in sources.items()
    ]
    records.sort(key=lambda item: item[0])
    return _digest(records)


def tool_fingerprint_data(tools: list[Any]) -> list[dict[str, Any]]:
    """Return stable tool descriptions including schemas, signatures, and tiers."""
    result = []
    for tool in tools:
        if isinstance(tool, dict):
            data = dict(tool)
        else:
            data = {
                "name": getattr(tool, "name", ""),
                "description": getattr(tool, "description", ""),
                "parameters": getattr(tool, "parameters", {}),
                "parameter_metadata": getattr(tool, "parameter_metadata", {}),
                "permission_tier": getattr(tool, "permission_tier", "read"),
            }
        result.append(data)
    return result


class ScenarioCache:
    """Store and replay one generated scenario suite under a cache-key filename."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def key(
        self,
        *,
        tools: list[Any],
        policy_overrides: dict[str, str] | None,
        seed: int,
        settings: dict[str, Any],
        source_fingerprint: str,
    ) -> str:
        return _digest(
            {
                "cache_schema_version": CACHE_SCHEMA_VERSION,
                "generator_schema_version": GENERATOR_SCHEMA_VERSION,
                "tools": tool_fingerprint_data(tools),
                "policy_overrides": policy_overrides or {},
                "seed": seed,
                "settings": settings,
                "agent_source": source_fingerprint,
            }
        )

    def load(self, key: str) -> list[dict[str, Any]] | None:
        path = self.directory / f".scenario-cache-{key}.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                return None
            scenarios = document["scenarios"]
            if (
                type(document.get("cache_schema_version")) is not int
                or document.get("cache_schema_version") != CACHE_SCHEMA_VERSION
                or type(document.get("generator_schema_version")) is not int
                or document.get("generator_schema_version") != GENERATOR_SCHEMA_VERSION
                or document.get("key") != key
                or not isinstance(scenarios, list)
                or document.get("scenarios_sha256") != _digest(scenarios)
            ):
                return None
            ids = []
            for item in scenarios:
                if not _valid_scenario(item):
                    return None
                ids.append(item["id"])
            if len(ids) != len(set(ids)):
                return None
            return scenarios
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def save(self, key: str, scenarios: list[dict[str, Any]]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        document = {
            "cache_schema_version": CACHE_SCHEMA_VERSION,
            "generator_schema_version": GENERATOR_SCHEMA_VERSION,
            "key": key,
            "scenarios_sha256": _digest(scenarios),
            "scenarios": scenarios,
        }
        path = self.directory / f".scenario-cache-{key}.json"
        fd, temporary = tempfile.mkstemp(
            prefix=".scenario-cache-", suffix=".tmp", dir=self.directory
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, sort_keys=True, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
