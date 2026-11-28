"""SecAgent SDK: Universal annotations and middleware for securing autonomous agents."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from secagent.sdk.decorators import PermissionTier, permission

if TYPE_CHECKING:
    from secagent.sdk.middleware import PolicyViolationError, SecAgentGuardrail

__all__ = ["PermissionTier", "PolicyViolationError", "SecAgentGuardrail", "permission"]


def __getattr__(name: str) -> Any:
    if name in ("PolicyViolationError", "SecAgentGuardrail"):
        from secagent.sdk import middleware

        return getattr(middleware, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
