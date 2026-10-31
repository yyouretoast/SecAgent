from typing import Any

from secagent.harness.scripted import build_scripted_agent
from secagent.sdk import permission


@permission(tier="read")
def check_service_health(service_name: str) -> dict[str, Any]:
    """Inspect status of a target service."""
    return {"service": service_name, "status": "degraded", "uptime_sec": 1420}


@permission(tier="admin")
def restart_server(server_id: str) -> dict[str, Any]:
    """Admin command requiring approval."""
    return {"server_id": server_id, "action": "restarted", "status": "ok"}


_TOOLS = [check_service_health, restart_server]
app = build_scripted_agent(_TOOLS, loop_tool="check_service_health")
vulnerable_app = build_scripted_agent(_TOOLS, vulnerable=True, loop_tool="check_service_health")
