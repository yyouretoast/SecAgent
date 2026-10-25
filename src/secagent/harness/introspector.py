"""Tool discovery and privilege-tier resolution (US-1.1, US-1.2)."""

from __future__ import annotations

import importlib
import inspect
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from langchain_core.tools import BaseTool

from secagent.sdk.decorators import VALID_TIERS

logger = logging.getLogger("secagent.harness")


class HarnessLoadError(Exception):
    """The agent entrypoint or policy file could not be loaded (a configuration problem)."""


TIER_ATTR = "_secagent_permission_tier"

_TIER_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("pure", ("calc", "format", "parse", "convert", "validate")),
    ("pay", ("pay", "refund", "trade", "charge", "transfer", "buy")),
    ("admin", ("drop", "delete", "restart", "kill", "exec", "bash", "deploy")),
    ("write", ("write", "update", "modify", "insert", "create")),
    ("net", ("network", "http", "webhook", "curl", "fetch", "post_")),
)


@dataclass
class ToolInfo:
    name: str
    description: str = ""
    parameters: dict[str, str] = field(default_factory=dict)
    permission_tier: str = "read"
    tool: Any = field(default=None, repr=False)


BASELINE_TOOLS: tuple[ToolInfo, ...] = (
    ToolInfo("execute_trade", "Executes equities trades", permission_tier="pay"),
    ToolInfo("restart_server", "Restarts cluster instances", permission_tier="admin"),
    ToolInfo("query_db", "Queries records", permission_tier="read"),
    ToolInfo("issue_refund", "Issues customer refund", permission_tier="pay"),
)


def resolve_permission_tier(
    name: str,
    explicit_tier: str | None = None,
    overrides: dict[str, str] | None = None,
) -> str:

    if explicit_tier:
        return explicit_tier
    if overrides and name in overrides:
        return overrides[name]
    lowered = name.lower()
    for tier, keywords in _TIER_KEYWORDS:
        if any(word in lowered for word in keywords):
            return tier
    return "read"


def load_policy_overrides(policy_path: str | Path) -> dict[str, str]:
    path = Path(policy_path)
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    overrides = data.get("tool_tier_overrides") or {}
    invalid = {str(k): v for k, v in overrides.items() if v not in VALID_TIERS}
    if invalid:
        raise HarnessLoadError(
            f"Invalid tier(s) in tool_tier_overrides of {path}: {invalid}. "
            f"Expected one of: {', '.join(VALID_TIERS)}"
        )
    return {str(k): str(v) for k, v in overrides.items()}


def tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", None) or getattr(tool, "__name__", "unknown_tool"))


def explicit_tier_of(tool: Any) -> str | None:
    for candidate in (tool, getattr(tool, "func", None), getattr(tool, "coroutine", None)):
        tier = getattr(candidate, TIER_ATTR, None)
        if isinstance(tier, str):
            return tier
    return None


def _dedupe(tools: list[Any]) -> list[Any]:
    seen: set[str] = set()
    unique: list[Any] = []
    for tool in tools:
        key = tool_name(tool)
        if key not in seen:
            seen.add(key)
            unique.append(tool)
    return unique


def graph_tool_dicts(target: Any) -> list[dict[str, Any]]:
    dicts: list[dict[str, Any]] = []
    nodes = getattr(target, "nodes", None)
    if not isinstance(nodes, dict):
        return dicts
    for node in nodes.values():
        for holder in (node, getattr(node, "bound", None)):
            tbn = getattr(holder, "tools_by_name", None)
            if isinstance(tbn, dict) and tbn not in dicts:
                dicts.append(tbn)
    return dicts


def discover_tools(target: Any, mod: Any = None) -> list[Any]:
    for owner in (target, mod):
        if owner is None:
            continue
        for attr in ("tools", "toolkit", "available_tools", "agent_tools"):
            value = getattr(owner, attr, None)
            if isinstance(value, (list, tuple, set)) and len(value) > 0:
                return _dedupe(list(value))

    graph_tools: list[Any] = []
    for tbn in graph_tool_dicts(target):
        graph_tools.extend(tbn.values())
    nodes = getattr(target, "nodes", None)
    if isinstance(nodes, dict):
        for node in nodes.values():
            for holder in (node, getattr(node, "bound", None)):
                listed = getattr(holder, "tools", None)
                if isinstance(listed, list):
                    graph_tools.extend(listed)
    if graph_tools:
        return _dedupe(graph_tools)

    for owner in (target, mod):
        for method in ("get_tools", "list_tools"):
            getter = getattr(owner, method, None) if owner is not None else None
            if callable(getter):
                try:
                    value = getter()
                except Exception as exc:
                    logger.warning("%s() raised %r while discovering tools", method, exc)
                    continue
                if isinstance(value, (list, tuple)) and len(value) > 0:
                    return _dedupe(list(value))

    for source in (mod, target):
        if source is not None and inspect.ismodule(source):
            found = [
                obj
                for _, obj in inspect.getmembers(source)
                if isinstance(obj, BaseTool) or (callable(obj) and hasattr(obj, TIER_ATTR))
            ]
            if found:
                return _dedupe(found)
    return []


def _parameters_of(tool: Any) -> dict[str, str]:
    args = getattr(tool, "args", None)
    if isinstance(args, dict) and args:
        return {name: str(spec.get("type", "any")) for name, spec in args.items()}
    func = getattr(tool, "func", None) or tool
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return {}
    return {p.name: str(p.annotation) for p in sig.parameters.values()}


def introspect_tools(tools: list[Any], overrides: dict[str, str] | None = None) -> list[ToolInfo]:
    infos: list[ToolInfo] = []
    for tool in tools:
        if isinstance(tool, ToolInfo):
            infos.append(tool)
            continue
        name = tool_name(tool)
        description = getattr(tool, "description", None) or getattr(tool, "__doc__", "") or ""
        infos.append(
            ToolInfo(
                name=name,
                description=str(description).strip(),
                parameters=_parameters_of(tool),
                permission_tier=resolve_permission_tier(name, explicit_tier_of(tool), overrides),
                tool=tool,
            )
        )
    return infos


def load_entrypoint(entrypoint: str) -> tuple[Any, Any]:
    cwd = str(Path.cwd())
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    mod_name, _, attr = entrypoint.partition(":")
    mod = importlib.import_module(mod_name)
    return (getattr(mod, attr) if attr else mod), mod


def introspect_entrypoint(
    entrypoint: str,
    policy_path: str | Path | None = None,
    on_error: str = "raise",
) -> list[ToolInfo]:
    overrides = load_policy_overrides(policy_path) if policy_path else {}
    try:
        target, mod = load_entrypoint(entrypoint)
        infos = introspect_tools(discover_tools(target, mod), overrides)
        if not infos:
            raise ValueError("no tools discovered")
    except Exception as exc:
        if on_error == "raise":
            raise HarnessLoadError(f"Cannot introspect {entrypoint!r}: {exc}") from exc
        logger.warning("Could not introspect %r (%s); using baseline tools", entrypoint, exc)
        return list(BASELINE_TOOLS)
    return infos
