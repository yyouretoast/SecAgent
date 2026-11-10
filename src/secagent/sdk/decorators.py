import functools
import inspect
from collections.abc import Callable
from typing import Any, Literal, get_args

PermissionTier = Literal["pure", "read", "write", "pay", "admin", "net"]
VALID_TIERS: tuple[str, ...] = get_args(PermissionTier)


def permission(tier: PermissionTier) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Universal SecAgent tool decorator specifying execution privilege tier.

    Applied to any tool in any LangGraph agent (DevOps, Finance, Support, Data).
    Works on both regular and ``async def`` tools (an async tool stays awaitable).

    Args:
        tier: One of 'pure', 'read', 'write', 'pay', 'admin', 'net'.
    """
    if tier not in VALID_TIERS:
        raise ValueError(
            f"Invalid permission tier {tier!r}. Expected one of: {', '.join(VALID_TIERS)}"
        )

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
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
