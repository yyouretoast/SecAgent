import functools
from collections.abc import Callable
from typing import Any, Literal

PermissionTier = Literal["pure", "read", "write", "pay", "admin", "net"]


def permission(tier: PermissionTier) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Universal SecAgent tool decorator specifying execution privilege tier.

    Applied to any tool in any LangGraph agent (DevOps, Finance, Support, Data).

    Args:
        tier: One of 'pure', 'read', 'write', 'pay', 'admin', 'net'.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        setattr(func, "_secagent_permission_tier", tier)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        setattr(wrapper, "_secagent_permission_tier", tier)
        return wrapper

    return decorator
