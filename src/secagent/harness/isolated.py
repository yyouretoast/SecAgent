"""Subprocess-isolated scenario execution with sanitized environment and hard kill on timeout."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from secagent.harness.executor import infer_task_context
from secagent.harness.runner import SandboxError

_SAFE_ENV_KEYS = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "PYTHONUTF8",
        "VIRTUAL_ENV",
        "PYTHONPATH",
    }
)


def build_sanitized_env(pass_env: Sequence[str] = (), *, cwd: str | None = None) -> dict[str, str]:
    """Build a minimal subprocess environment stripping host credentials unless allowlisted."""
    allowed = {k.upper() for k in _SAFE_ENV_KEYS} | {k.upper() for k in pass_env}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    work_dir = cwd or str(Path.cwd())
    extra_paths = [work_dir]
    existing_pp = env.get("PYTHONPATH", "")
    if existing_pp:
        extra_paths.extend(p for p in existing_pp.split(os.pathsep) if p)
    env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(extra_paths))
    env["PYTHONUTF8"] = "1"
    return env


def _raise_worker_error(payload: dict[str, Any], stderr: str) -> None:
    err = str(payload.get("error") or stderr or "Isolated worker error")
    if payload.get("error_type") == "SandboxError":
        raise SandboxError(err)
    raise RuntimeError(err)


def introspect_isolated(
    agent_entrypoint: str,
    policy_overrides: dict[str, str],
    *,
    timeout_s: float = 30.0,
    block_network: bool = False,
    pass_env: Sequence[str] = (),
    cwd: str | Path | None = None,
) -> tuple[list[Any], bool, str]:
    """Introspect an untrusted agent inside a sanitized child subprocess (zero host import)."""
    from secagent.generator import ToolMetadata

    work_dir = str(Path(cwd).resolve()) if cwd is not None else str(Path.cwd())
    env = build_sanitized_env(pass_env, cwd=work_dir)
    with tempfile.TemporaryDirectory(prefix="secagent-iso-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        req_file = tmp_path / "introspect_req.json"
        resp_file = tmp_path / "introspect_resp.json"
        req_file.write_text(
            json.dumps(
                {
                    "mode": "introspect",
                    "agent_entrypoint": agent_entrypoint,
                    "policy_overrides": policy_overrides,
                    "block_network": block_network,
                }
            ),
            encoding="utf-8",
        )
        proc = subprocess.Popen(
            [sys.executable, "-m", "secagent.harness._worker", str(req_file), str(resp_file)],
            cwd=work_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _, stderr = proc.communicate(timeout=timeout_s + 5.0)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            proc.communicate()
            raise RuntimeError(
                f"Isolated introspection timed out for '{agent_entrypoint}'"
            ) from exc

        if resp_file.is_file():
            payload = json.loads(resp_file.read_text(encoding="utf-8"))
            if payload.get("status") == "ok":
                tools = [
                    ToolMetadata(
                        name=str(item["name"]),
                        description=str(item.get("description") or ""),
                        parameters=dict(item.get("parameters") or {}),
                        permission_tier=str(item.get("permission_tier") or "read"),
                        parameter_metadata=dict(item.get("parameter_metadata") or {}),
                        tier_source=str(item.get("tier_source") or "default"),
                    )
                    for item in (payload.get("tools") or [])
                ]
                return (
                    tools,
                    bool(payload.get("is_runnable", False)),
                    str(payload.get("source_fingerprint") or "isolated"),
                )
            _raise_worker_error(payload, stderr)
        raise RuntimeError(
            f"Isolated introspection exited with {proc.returncode}: {stderr.strip()}"
        )


def run_isolated_scenarios(
    agent_entrypoint: str,
    scenario_dicts: list[dict[str, Any]],
    policy_overrides: dict[str, str],
    *,
    timeout_s: float = 30.0,
    startup_grace_s: float = 3.0,
    strict_sandbox: bool = True,
    mock_unclassified: bool = True,
    block_network: bool = False,
    pass_env: Sequence[str] = (),
    cwd: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Run scenarios in a child Python subprocess with authoritative hard kill on timeout."""
    if not scenario_dicts:
        return []

    work_dir = str(Path(cwd).resolve()) if cwd is not None else str(Path.cwd())
    env = build_sanitized_env(pass_env, cwd=work_dir)
    traces: list[dict[str, Any]] = []
    parent_timeout = timeout_s + startup_grace_s
    # Inner harness timeout exceeds parent watchdog so hung agents trigger true proc.kill().
    worker_inner_timeout = parent_timeout + 5.0

    with tempfile.TemporaryDirectory(prefix="secagent-iso-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        for idx, scn in enumerate(scenario_dicts):
            scn_id = str(scn.get("id") or scn.get("scenario_id") or f"SCN-{idx + 1:03d}")
            req_file = tmp_path / f"req_{idx}.json"
            resp_file = tmp_path / f"resp_{idx}.json"
            req_file.write_text(
                json.dumps(
                    {
                        "mode": "execute",
                        "agent_entrypoint": agent_entrypoint,
                        "scenarios": [scn],
                        "policy_overrides": policy_overrides,
                        "timeout_s": worker_inner_timeout,
                        "strict_sandbox": strict_sandbox,
                        "mock_unclassified": mock_unclassified,
                        "block_network": block_network,
                    }
                ),
                encoding="utf-8",
            )

            started_ns = time.time_ns()
            proc = subprocess.Popen(
                [sys.executable, "-m", "secagent.harness._worker", str(req_file), str(resp_file)],
                cwd=work_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _, stderr = proc.communicate(timeout=parent_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                end_ns = time.time_ns()
                traces.append(
                    {
                        "scenario_id": scn_id,
                        "execution_id": str(uuid.uuid4()),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "caller_role": str(scn.get("caller_role") or "guest"),
                        "task_context": infer_task_context(scn),
                        "metadata": {
                            "framework": "isolated_subprocess",
                            "is_benign": bool(scn.get("is_benign", False)),
                        },
                        "spans": [
                            {
                                "span_id": f"iso-timeout-{uuid.uuid4().hex[:8]}",
                                "step_index": 0,
                                "span_type": "agent.run",
                                "name": "isolated_subprocess",
                                "start_time_ns": started_ns,
                                "end_time_ns": end_ns,
                                "permission_tier": "none",
                                "approval_granted": None,
                                "input_parameters": {},
                                "output_result": None,
                                "is_error": True,
                                "error_message": "Isolated subprocess killed after timeout",
                            }
                        ],
                    }
                )
                continue

            if resp_file.is_file():
                payload = json.loads(resp_file.read_text(encoding="utf-8"))
                if payload.get("status") == "ok":
                    traces.extend(payload.get("traces") or [])
                    continue
                _raise_worker_error(payload, stderr)

            raise RuntimeError(f"Isolated worker exited with {proc.returncode}: {stderr.strip()}")

    return traces
