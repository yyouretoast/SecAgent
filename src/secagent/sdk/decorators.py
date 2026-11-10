import functools
import inspect
from collections.abc import Callable
from typing import Any, Literal, get_args

PermissionTier = Literal["pure", "read", "write", "pay", "admin", "net"]
VALID_TIERS: tuple[str, ...] = get_args(PermissionTier)


def permission(tier: PermissionTier) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Universal SecAgent tool decorator specifying execution privilege tier.

    Applied to any tool in any LangGraph agent (DevOps, Finance, Support, Data).
    Works on regular functions, async functions, and LangChain tools.

    Args:
        tier: One of 'pure', 'read', 'write', 'pay', 'admin', 'net'.
    """
    if tier not in VALID_TIERS:
        raise ValueError(
            f"Invalid permission tier {tier!r}. Expected one of: {', '.join(VALID_TIERS)}"
        )

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        # Preserve LangChain StructuredTool objects and their metadata.
        if hasattr(func, "name") and not inspect.isfunction(func):
            setattr(func, "_secagent_permission_tier", tier)

            inner_func = getattr(func, "func", None)
            if inner_func is not None:
                setattr(inner_func, "_secagent_permission_tier", tier)

            return func

        setattr(func, "_secagent_permission_tier", tier)

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await func(*args, **kwargs)

            wrapper: Callable[..., Any] = async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                return func(*args, **kwargs)

            wrapper = sync_wrapper

        setattr(wrapper, "_secagent_permission_tier", tier)
        return wrapper

    return decorator