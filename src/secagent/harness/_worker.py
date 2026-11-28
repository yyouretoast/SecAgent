"""Isolated child worker process for SecAgent subprocess sandboxing."""

from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path
from typing import Any

from rich.console import Console


def _install_network_block() -> None:
    """Block outbound network, UDP, DNS, and child process escape via PEP 578 audit hook.

    Internal ``socket.socketpair()`` calls (used by CPython's ``asyncio`` on Windows)
    are temporarily permitted via a thread-local guard while all direct TCP/UDP/DNS
    and child-process escape attempts—including Windows ProactorEventLoop async sockets—
    are blocked permanently for this interpreter process.
    """
    orig_socketpair = getattr(socket, "socketpair", None)
    state = threading.local()

    if callable(orig_socketpair):

        def _guarded_socketpair(*args: Any, **kwargs: Any) -> Any:
            prev = getattr(state, "allow_socketpair", False)
            state.allow_socketpair = True
            try:
                return orig_socketpair(*args, **kwargs)
            finally:
                state.allow_socketpair = prev

        socket.socketpair = _guarded_socketpair  # type: ignore[assignment]

    blocked_events = frozenset(
        {
            "socket.connect",
            "socket.sendto",
            "socket.sendmsg",
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyaddr",
            "subprocess.Popen",
            "os.system",
            "os.posix_spawn",
            "os.exec",
        }
    )

    def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
        if event not in blocked_events:
            return
        if event == "socket.connect" and getattr(state, "allow_socketpair", False):
            return
        raise PermissionError(
            f"Outbound network/process event '{event}' is blocked by SecAgent isolated sandbox"
        )

    sys.addaudithook(_audit_hook)

    # On Windows, ProactorEventLoop uses _overlapped.ConnectEx directly without firing
    # the 'socket.connect' audit event; block asyncio transport creation explicitly too.
    import asyncio

    async def _blocked_async_connect(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise PermissionError(
            "Outbound async network access is blocked by SecAgent isolated sandbox"
        )

    asyncio.BaseEventLoop.create_connection = _blocked_async_connect  # type: ignore[method-assign]
    asyncio.BaseEventLoop.create_datagram_endpoint = _blocked_async_connect  # type: ignore[method-assign]
    if sys.platform == "win32":
        import asyncio.windows_events as _win_events

        def _blocked_proactor_connect(self: Any, *args: Any, **kwargs: Any) -> Any:
            raise PermissionError(
                "Outbound async network access is blocked by SecAgent isolated sandbox"
            )

        _win_events.IocpProactor.connect = _blocked_proactor_connect  # type: ignore[assignment]


def _load_target_and_tools(
    entrypoint: str, overrides: dict[str, str]
) -> tuple[Any, Any, list[Any]]:
    from secagent.generator import ScenarioGenerator
    from secagent.harness.executor import is_runnable_target
    from secagent.harness.introspector import discover_tools, load_entrypoint

    target, mod = load_entrypoint(entrypoint)
    if callable(target) and not is_runnable_target(target):
        try:
            built = target()
            if is_runnable_target(built):
                target = built
        except TypeError:
            pass
    raw_tools = discover_tools(target, mod)
    discovered = ScenarioGenerator().introspect_tools(raw_tools, policy_overrides=overrides)
    return target, mod, discovered


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        sys.stderr.write(
            "Usage: python -m secagent.harness._worker <request.json> <response.json>\n"
        )
        return 2

    req_path = Path(args[0])
    resp_path = Path(args[1])
    request = json.loads(req_path.read_text(encoding="utf-8"))

    if request.get("block_network"):
        _install_network_block()

    mode = str(request.get("mode") or "execute")
    entrypoint = str(request["agent_entrypoint"])
    overrides = dict(request.get("policy_overrides") or {})

    try:
        target, mod, discovered = _load_target_and_tools(entrypoint, overrides)
        if mode == "introspect":
            from secagent.generator.cache import agent_source_fingerprint
            from secagent.harness.executor import is_runnable_target

            serialized_tools = [
                {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                    "permission_tier": t.permission_tier,
                    "parameter_metadata": {
                        k: {
                            sk: (
                                sv
                                if isinstance(sv, (str, int, float, bool, list, dict)) or sv is None
                                else str(sv)
                            )
                            for sk, sv in v.items()
                        }
                        if isinstance(v, dict)
                        else v
                        for k, v in (t.parameter_metadata or {}).items()
                    },
                    "tier_source": getattr(t, "tier_source", "default"),
                }
                for t in discovered
            ]
            resp_path.write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "tools": serialized_tools,
                        "is_runnable": is_runnable_target(target),
                        "source_fingerprint": agent_source_fingerprint(mod),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            return 0

        from secagent.harness.executor import execute_scenarios_with_telemetry

        scenarios = list(request.get("scenarios") or [])
        timeout_s = float(request.get("timeout_s") or 30.0)
        strict_sandbox = bool(request.get("strict_sandbox", True))
        mock_unclassified = bool(request.get("mock_unclassified", True))

        traces = execute_scenarios_with_telemetry(
            target,
            mod,
            discovered,
            scenarios,
            overrides,
            console=Console(quiet=True),
            timeout_s=timeout_s,
            quiet=True,
            strict_sandbox=strict_sandbox,
            mock_unclassified=mock_unclassified,
        )
        resp_path.write_text(
            json.dumps({"status": "ok", "traces": traces}, indent=2),
            encoding="utf-8",
        )
        return 0
    except Exception as exc:
        resp_path.write_text(
            json.dumps(
                {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
