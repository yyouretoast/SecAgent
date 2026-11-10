from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import BaseTool

from secagent.harness.introspector import (
    TIER_ATTR,
    explicit_tier_of,
    graph_tool_dicts,
    resolve_permission_tier,
    tool_name,
)

DRY_RUN_TIERS = frozenset({"pay", "admin", "write", "net"})
MOCK_RESPONSE: dict[str, Any] = {"status": "mock_success", "dry_run": True}
_MARK = "_secagent_virtualized"
_ORIGINAL = "_secagent_original"


@dataclass
class ToolCallRecord:
    """One tool invocation seen by the sandbox."""

    tool_name: str
    tier: str
    arguments: dict[str, Any]
    mocked: bool


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
    patched: list[str] = field(default_factory=list)
    calls: list[ToolCallRecord] = field(default_factory=list)

    def wrap_callable(
        self, fn: Callable[..., Any], name: str | None = None, tier: str | None = None
    ) -> Callable[..., Any]:

        if getattr(fn, _MARK, False):
            fn = getattr(fn, _ORIGINAL, fn)
        tool_label = name or getattr(fn, "__name__", "unknown_tool")
        resolved = tier or resolve_permission_tier(tool_label, explicit_tier_of(fn), self.overrides)
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                mocked = self._record(fn, tool_label, resolved, args, kwargs)
                return dict(MOCK_RESPONSE) if mocked else await fn(*args, **kwargs)

            wrapper: Callable[..., Any] = awrapper
        else:

            @functools.wraps(fn)
            def swrapper(*args: Any, **kwargs: Any) -> Any:
                mocked = self._record(fn, tool_label, resolved, args, kwargs)
                return dict(MOCK_RESPONSE) if mocked else fn(*args, **kwargs)

            wrapper = swrapper
        setattr(wrapper, TIER_ATTR, resolved)
        setattr(wrapper, _MARK, True)
        setattr(wrapper, _ORIGINAL, fn)
        return wrapper

    def _record(self, fn, label: str, tier: str, args, kwargs) -> bool:
        mocked = self.dry_run and tier in DRY_RUN_TIERS
        self.calls.append(ToolCallRecord(label, tier, _bind_arguments(fn, args, kwargs), mocked))
        return mocked

    # LangChain tools
    def wrap_tool(self, tool: BaseTool) -> BaseTool:

        update: dict[str, Any] = {}
        name = tool_name(tool)
        tier = resolve_permission_tier(name, explicit_tier_of(tool), self.overrides)
        func = getattr(tool, "func", None)
        coroutine = getattr(tool, "coroutine", None)

        if callable(func):
            update["func"] = self.wrap_callable(func, name, tier)
        if callable(coroutine):
            update["coroutine"] = self.wrap_callable(coroutine, name, tier)
        if not update:
            for attr in ("_run", "_arun"):
                if getattr(type(tool), attr, None) is not getattr(BaseTool, attr, None):
                    update[attr] = self.wrap_callable(getattr(tool, attr), name, tier)
        return tool.model_copy(update=update) if update else tool

    def wrap(self, tool: Any) -> Any:
        """Wrap either kind of tool."""
        return self.wrap_tool(tool) if isinstance(tool, BaseTool) else self.wrap_callable(tool)

    @contextmanager
    def virtualize(self, target: Any, mod: Any = None) -> Iterator[VirtualizedToolWrapper]:
        undo: list[Callable[[], None]] = []

        for tbn in graph_tool_dicts(target):
            for key, tool in list(tbn.items()):
                tbn[key] = self.wrap(tool)
                self.patched.append(tool_name(tool))
                undo.append(lambda d=tbn, k=key, t=tool: d.__setitem__(k, t))

        for owner in (target, mod):
            for attr in ("tools", "toolkit", "available_tools", "agent_tools"):
                items = getattr(owner, attr, None) if owner is not None else None
                if isinstance(items, list):
                    original = list(items)
                    items[:] = [self.wrap(t) for t in original]
                    self.patched.extend(tool_name(t) for t in original)
                    undo.append(lambda lst=items, orig=original: lst.__setitem__(slice(None), orig))

        if mod is not None and inspect.ismodule(mod):
            for attr, obj in inspect.getmembers(mod):
                if callable(obj) and hasattr(obj, TIER_ATTR) and not isinstance(obj, BaseTool):
                    setattr(mod, attr, self.wrap_callable(obj, attr))
                    self.patched.append(attr)
                    undo.append(lambda m=mod, a=attr, o=obj: setattr(m, a, o))
        try:
            yield self
        finally:
            if not self.keep_patched:
                for restore in reversed(undo):
                    restore()
