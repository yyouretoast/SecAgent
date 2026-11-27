"""Tool discovery and privilege-tier resolution (US-1.1, US-1.2)."""

from __future__ import annotations

import importlib
import inspect
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

try:
    from langchain_core.tools import BaseTool
except ImportError:  # pragma: no cover - optional langgraph extra

    class BaseTool:  # type: ignore[no-redef]
        """Placeholder when langchain-core is not installed."""


from secagent.sdk.decorators import VALID_TIERS

logger = logging.getLogger("secagent.harness")


class HarnessLoadError(Exception):
    """The agent entrypoint or policy file could not be loaded (a configuration problem)."""


TIER_ATTR = "_secagent_permission_tier"
TierSource = Literal["decorator", "override", "heuristic", "default"]

_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+")
_READ_PREFIX_TOKENS = frozenset(
    {
        "get",
        "read",
        "list",
        "lookup",
        "describe",
        "view",
        "show",
        "find",
        "count",
        "check",
        "search",
        "query",
    }
)
_PURE_PREFIX_TOKENS = frozenset({"calc", "calculate", "format", "parse", "convert", "validate"})
_ASYNC_WRAPPER_PREFIXES = frozenset({"async", "safe", "try"})
_TIER_KEYWORDS: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    (
        "pay",
        frozenset({"pay", "refund", "trade", "charge", "transfer", "buy", "wire", "checkout"}),
        frozenset({"payment", "invoice", "billing"}),
    ),
    (
        "admin",
        frozenset(
            {
                "drop",
                "delete",
                "remove",
                "rm",
                "terminate",
                "wipe",
                "destroy",
                "purge",
                "restart",
                "kill",
                "exec",
                "execute",
                "bash",
                "deploy",
                "sudo",
                "grant",
                "revoke",
                "eval",
                "publish",
                "chmod",
                "chown",
            }
        ),
        frozenset({"ssh", "shell", "command", "cmd", "lambda"}),
    ),
    (
        "net",
        frozenset(
            {
                "network",
                "http",
                "https",
                "webhook",
                "webhooks",
                "curl",
                "fetch",
                "post",
                "socket",
                "smtp",
                "upload",
            }
        ),
        frozenset({"request", "url", "api"}),
    ),
    (
        "write",
        frozenset(
            {
                "write",
                "update",
                "modify",
                "insert",
                "create",
                "send",
                "submit",
                "put",
                "patch",
                "append",
                "save",
                "set",
                "edit",
                "upsert",
            }
        ),
        frozenset({"email", "sql"}),
    ),
    (
        "pure",
        _PURE_PREFIX_TOKENS,
        frozenset(),
    ),
)


def _tokenize_tool_name(name: str) -> list[str]:
    return [tok.lower() for tok in _TOKEN_RE.findall(name)]


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


def resolve_permission_tier_with_source(
    name: str,
    explicit_tier: str | None = None,
    overrides: dict[str, str] | None = None,
) -> tuple[str, TierSource]:
    """Resolve permission tier and report where the classification originated."""
    if explicit_tier:
        return explicit_tier, "decorator"
    if overrides and name in overrides:
        return overrides[name], "override"
    tokens = _tokenize_tool_name(name)
    token_set = set(tokens)
    eff = tokens[1:] if len(tokens) >= 2 and tokens[0] in _ASYNC_WRAPPER_PREFIXES else tokens
    starts_read = bool(eff) and (eff[0] in _READ_PREFIX_TOKENS or eff[-1] == "query")
    starts_pure = bool(eff) and eff[0] in _PURE_PREFIX_TOKENS
    for tier, action_tokens, noun_tokens in _TIER_KEYWORDS:
        if token_set & action_tokens:
            return tier, "heuristic"
        skip_nouns = starts_read or (starts_pure and tier in ("write", "net"))
        if not skip_nouns and (token_set & noun_tokens):
            return tier, "heuristic"
    return "read", "default"


def resolve_permission_tier(
    name: str,
    explicit_tier: str | None = None,
    overrides: dict[str, str] | None = None,
) -> str:
    return resolve_permission_tier_with_source(name, explicit_tier, overrides)[0]


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
        if candidate is None:
            continue
        unwrapped = getattr(candidate, "_secagent_original", candidate)
        for target in (unwrapped, candidate):
            tier = getattr(target, TIER_ATTR, None)
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


def graph_tool_dicts(target: Any, _visited: set[int] | None = None) -> list[dict[str, Any]]:
    dicts: list[dict[str, Any]] = []
    seen = _visited if _visited is not None else set()
    nodes = getattr(target, "nodes", None)
    if not isinstance(nodes, dict):
        return dicts
    for node in nodes.values():
        if id(node) in seen:
            continue
        seen.add(id(node))
        for holder in (node, getattr(node, "bound", None)):
            if holder is None:
                continue
            tbn = getattr(holder, "tools_by_name", None)
            if isinstance(tbn, dict) and tbn not in dicts:
                dicts.append(tbn)
            if isinstance(getattr(holder, "nodes", None), dict):
                for sub_tbn in graph_tool_dicts(holder, seen):
                    if sub_tbn not in dicts:
                        dicts.append(sub_tbn)
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
        seen: set[int] = set()
        stack = list(nodes.values())
        while stack:
            node = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            for holder in (node, getattr(node, "bound", None)):
                if holder is None:
                    continue
                listed = getattr(holder, "tools", None)
                if isinstance(listed, list):
                    graph_tools.extend(listed)
                sub_nodes = getattr(holder, "nodes", None)
                if isinstance(sub_nodes, dict):
                    stack.extend(sub_nodes.values())
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
    func = getattr(tool, "func", None) or getattr(tool, "coroutine", None) or tool
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
