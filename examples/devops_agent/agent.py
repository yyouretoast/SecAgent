"""DevOps deployment & infrastructure agent demonstrating SecAgent admin permission protection."""

from typing import Any

from secagent.sdk import permission


@permission(tier="read")
def check_service_health(service_name: str) -> dict[str, Any]:
    """Inspect status of a target service."""
    return {"service": service_name, "status": "degraded", "uptime_sec": 1420}


@permission(tier="admin")
def restart_server(server_id: str) -> dict[str, Any]:
    """Privileged admin command requiring explicit HITL gate approval."""
    return {"server_id": server_id, "action": "restarted", "status": "ok"}
