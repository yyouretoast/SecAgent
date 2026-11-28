from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

from langchain_core.tools import BaseTool

from secagent.harness.introspector import (
    TIER_ATTR,
    TierSource,
    explicit_tier_of,
    graph_tool_dicts,
    resolve_permission_tier_with_source,
    tool_name,
)

DRY_RUN_TIERS = frozenset({"pay", "admin", "write", "net"})
MOCK_RESPONSE: dict[str, Any] = {"status": "mock_success", "dry_run": True}
_MARK = "_secagent_virtualized"
_ORIGINAL = "_secagent_original"
_ORIGINAL_TOOL = "_secagent_original_tool"


def _is_async_callable(fn: Any) -> bool:
    if inspect.iscoroutinefunction(fn):
        return True
    call_attr = getattr(fn, "__call__", None)
    return bool(callable(call_attr) and inspect.iscoroutinefunction(call_attr))


def _json_safe_preview(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:120]
    return repr(value)[:120]


def _unwrap_tool(tool: Any) -> Any:
    current = tool
    seen: set[int] = set()
    while id(current) not in seen:
        seen.add(id(current))
        orig = getattr(current, _ORIGINAL_TOOL, None)
        if orig is not None:
            current = orig
            continue
        if getattr(current, _MARK, False):
            orig_fn = getattr(current, _ORIGINAL, None)
            if orig_fn is not None:
                current = orig_fn
                continue
        break
    return current


@dataclass
class ToolCallRecord:
    """One tool invocation seen by the sandbox."""

    tool_name: str
    tier: str
    arguments: dict[str, Any]
    mocked: bool
    output: Any = None


def _bind_arguments(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]):
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
    except (TypeError, ValueError):
        return {**{f"arg{i}": a for i, a in enumerate(args)}, **kwargs}
    return dict(bound.arguments)


@dataclass
class VirtualizedToolWrapper:
    overrides: dict[str, str] | None = None
    dry_run: bool = True
    keep_patched: bool = False
    mock_unclassified: bool = False
    mock_mode: Literal["minimal", "rich"] = "minimal"
    taint_read_outputs: str | None = None
    patched: list[str] = field(default_factory=list)
    calls: list[ToolCallRecord] = field(default_factory=list)
    _undo_stack: list[Callable[[], None]] = field(default_factory=list, repr=False)

    def restore(self) -> None:
        """Restore all patched targets back to their original unwrapped tools."""
        while self._undo_stack:
            undo = self._undo_stack.pop()
            undo()

    def _build_mock_response(self, label: str, bound_args: dict[str, Any]) -> dict[str, Any]:
        if self.mock_mode == "rich":
            echo = {str(k): _json_safe_preview(v) for k, v in list(bound_args.items())[:5]}
            return {**MOCK_RESPONSE, "tool": label, "echo": echo}
        return dict(MOCK_RESPONSE)

    def _maybe_taint(self, tier: str, result: Any) -> Any:
        if not self.taint_read_outputs or tier not in ("read", "net"):
            return result
        if isinstance(result, dict):
            return {**result, "_untrusted_note": self.taint_read_outputs}
        if isinstance(result, str):
            return f"{result}\n\n{self.taint_read_outputs}"
        if isinstance(result, list):
            if result and isinstance(result[0], dict):
                return [{**result[0], "_untrusted_note": self.taint_read_outputs}, *result[1:]]
            return [*result, self.taint_read_outputs]
        return {"data": result, "_untrusted_note": self.taint_read_outputs}

    def wrap_callable(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        tier: str | None = None,
        *,
        tier_source: TierSource | None = None,
    ) -> Callable[..., Any]:

        if getattr(fn, _MARK, False):
            fn = getattr(fn, _ORIGINAL, fn)
        tool_label = str(name or getattr(fn, "__name__", "unknown_tool"))
        if tier is not None:
            resolved = tier
            resolved_source: TierSource = tier_source or "decorator"
        else:
            resolved, resolved_source = resolve_permission_tier_with_source(
                tool_label, explicit_tier_of(fn), self.overrides
            )
        if _is_async_callable(fn):

            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                mocked, bound, rec = self._record(
                    fn, tool_label, resolved, resolved_source, args, kwargs
                )
                result = (
                    self._build_mock_response(tool_label, bound)
                    if mocked
                    else await fn(*args, **kwargs)
                )
                final = self._maybe_taint(resolved, result)
                if not mocked or (self.taint_read_outputs and resolved in ("read", "net")):
                    rec.output = final
                return final

            wrapper: Callable[..., Any] = awrapper
        else:

            @functools.wraps(fn)
            def swrapper(*args: Any, **kwargs: Any) -> Any:
                mocked, bound, rec = self._record(
                    fn, tool_label, resolved, resolved_source, args, kwargs
                )
                result = (
                    self._build_mock_response(tool_label, bound) if mocked else fn(*args, **kwargs)
                )
                final = self._maybe_taint(resolved, result)
                if not mocked or (self.taint_read_outputs and resolved in ("read", "net")):
                    rec.output = final
                return final

            wrapper = swrapper
        if resolved_source == "decorator":
            setattr(wrapper, TIER_ATTR, resolved)
        setattr(wrapper, _MARK, True)
        setattr(wrapper, _ORIGINAL, fn)
        return wrapper

    def _record(
        self,
        fn: Callable[..., Any],
        label: str,
        tier: str,
        tier_source: TierSource,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[bool, dict[str, Any], ToolCallRecord]:
        mocked = self.dry_run and (
            tier in DRY_RUN_TIERS or (self.mock_unclassified and tier_source == "default")
        )
        bound = _bind_arguments(fn, args, kwargs)
        rec = ToolCallRecord(label, tier, bound, mocked)
        self.calls.append(rec)
        return mocked, bound, rec

    # LangChain tools
    def wrap_tool(self, tool: BaseTool) -> BaseTool:
        orig_tool = _unwrap_tool(tool)
        if not isinstance(orig_tool, BaseTool):
            orig_tool = tool
        update: dict[str, Any] = {}
        name = tool_name(orig_tool)
        tier, tier_source = resolve_permission_tier_with_source(
            name, explicit_tier_of(orig_tool), self.overrides
        )
        func = getattr(orig_tool, "func", None)
        coroutine = getattr(orig_tool, "coroutine", None)

        if callable(func):
            update["func"] = self.wrap_callable(func, name, tier, tier_source=tier_source)
        if callable(coroutine):
            update["coroutine"] = self.wrap_callable(coroutine, name, tier, tier_source=tier_source)
        if not update:
            for attr in ("_run", "_arun"):
                if getattr(type(orig_tool), attr, None) is not getattr(BaseTool, attr, None):
                    update[attr] = self.wrap_callable(
                        getattr(orig_tool, attr), name, tier, tier_source=tier_source
                    )
        if not update:
            return orig_tool
        wrapped = orig_tool.model_copy(update=update)
        try:
            object.__setattr__(wrapped, _ORIGINAL_TOOL, orig_tool)
        except Exception:
            pass
        return wrapped

    def wrap(self, tool: Any) -> Any:
        """Wrap either kind of tool."""
        unwrapped = _unwrap_tool(tool)
        return (
            self.wrap_tool(unwrapped)
            if isinstance(unwrapped, BaseTool)
            else self.wrap_callable(unwrapped)
        )

    @contextmanager
    def virtualize(self, target: Any, mod: Any = None) -> Iterator[VirtualizedToolWrapper]:
        undo: list[Callable[[], None]] = []

        for tbn in graph_tool_dicts(target):
            for key, tool in list(tbn.items()):
                orig = _unwrap_tool(tool)
                tbn[key] = self.wrap(orig)
                self.patched.append(tool_name(orig))
                undo.append(functools.partial(tbn.__setitem__, key, orig))

        nodes = getattr(target, "nodes", None)
        if isinstance(nodes, dict):
            visited: set[int] = set()
            stack = list(nodes.values())
            while stack:
                node = stack.pop()
                if id(node) in visited:
                    continue
                visited.add(id(node))
                for holder in (node, getattr(node, "bound", None)):
                    if holder is None:
                        continue
                    listed = getattr(holder, "tools", None)
                    if isinstance(listed, list) and listed:
                        originals = [_unwrap_tool(t) for t in listed]
                        listed[:] = [self.wrap(t) for t in originals]
                        self.patched.extend(tool_name(t) for t in originals)
                        undo.append(functools.partial(listed.__setitem__, slice(None), originals))
                    sub_nodes = getattr(holder, "nodes", None)
                    if isinstance(sub_nodes, dict):
                        stack.extend(sub_nodes.values())

        for owner in (target, mod):
            for attr in ("tools", "toolkit", "available_tools", "agent_tools"):
                items = getattr(owner, attr, None) if owner is not None else None
                if isinstance(items, list):
                    originals = [_unwrap_tool(t) for t in items]
                    items[:] = [self.wrap(t) for t in originals]
                    self.patched.extend(tool_name(t) for t in originals)
                    undo.append(functools.partial(items.__setitem__, slice(None), originals))
                elif isinstance(items, tuple) and items:
                    originals = [_unwrap_tool(t) for t in items]
                    try:
                        setattr(owner, attr, tuple(self.wrap(t) for t in originals))
                        self.patched.extend(tool_name(t) for t in originals)
                        undo.append(functools.partial(setattr, owner, attr, tuple(originals)))
                    except (AttributeError, TypeError):
                        pass
                elif isinstance(items, set) and items:
                    originals = [_unwrap_tool(t) for t in items]
                    try:
                        wrapped_set = {self.wrap(t) for t in originals}
                    except TypeError:
                        wrapped_set = None
                    if wrapped_set is not None:
                        try:
                            setattr(owner, attr, wrapped_set)
                            self.patched.extend(tool_name(t) for t in originals)
                            undo.append(functools.partial(setattr, owner, attr, set(originals)))
                        except (AttributeError, TypeError):
                            pass

        if mod is not None and inspect.ismodule(mod):
            for attr, obj in inspect.getmembers(mod):
                if isinstance(obj, BaseTool):
                    orig = _unwrap_tool(obj)
                    setattr(mod, attr, self.wrap_tool(orig))
                    self.patched.append(tool_name(orig))
                    undo.append(functools.partial(setattr, mod, attr, orig))
                elif callable(obj) and hasattr(obj, TIER_ATTR):
                    orig = _unwrap_tool(obj)
                    canon_name = tool_name(orig)
                    setattr(mod, attr, self.wrap_callable(orig, canon_name))
                    self.patched.append(canon_name)
                    undo.append(functools.partial(setattr, mod, attr, orig))

        self._undo_stack.extend(undo)
        try:
            yield self
        finally:
            if not self.keep_patched:
                self.restore()
