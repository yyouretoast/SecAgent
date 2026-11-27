"""MCP (Model Context Protocol) supply-chain poisoning & rug-pull scanner (ASI04)."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secagent.engine.models import EvaluationResult, PolicyViolation
from secagent.engine.rules.tool_poisoning import scan_tool_definitions


@dataclass(frozen=True)
class MCPToolSpec:
    """Normalized MCP tool definition extracted from a manifest or config."""

    name: str
    description: str
    input_schema: dict[str, Any]
    server: str = ""
    annotations: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        return f"{self.server}:{self.name}" if self.server else self.name

    @property
    def parameter_metadata(self) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        props = self.input_schema.get("properties")
        if isinstance(props, dict):
            meta.update({str(k): v for k, v in props.items()})
        for extra_key in (
            "$defs",
            "definitions",
            "title",
            "description",
            "examples",
            "default",
            "enum",
            "anyOf",
            "oneOf",
            "allOf",
            "items",
            "additionalProperties",
            "patternProperties",
        ):
            if extra_key in self.input_schema:
                meta[f"__schema_{extra_key}"] = self.input_schema[extra_key]
        if self.annotations:
            meta["__annotations"] = self.annotations
        if self.output_schema:
            meta["__outputSchema"] = self.output_schema
        return meta

    def canonical_hash(self) -> str:
        payload: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.annotations:
            payload["annotations"] = self.annotations
        if self.output_schema:
            payload["outputSchema"] = self.output_schema
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def load_mcp_manifest(
    path: str | Path,
    *,
    _visited: frozenset[Path] | None = None,
    _base_dir: Path | None = None,
) -> list[MCPToolSpec]:
    """Load MCP tool definitions from a ``tools/list`` JSON, JSON-RPC response, or ``mcpServers`` config."""
    source = Path(path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"MCP manifest not found: {source}")
    base_dir = (_base_dir or source.parent).resolve()
    visited = _visited or frozenset()
    if source in visited:
        raise ValueError(f"Cyclic MCP manifest reference detected: {source}")
    next_visited = visited | {source}
    raw = json.loads(source.read_text(encoding="utf-8"))
    specs: list[MCPToolSpec] = []

    def _add_tools(items: Any, server: str) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, Mapping) or not item.get("name"):
                continue
            schema = item.get("inputSchema") or item.get("input_schema") or {}
            annotations = item.get("annotations") or {}
            out_schema = item.get("outputSchema") or item.get("output_schema") or {}
            specs.append(
                MCPToolSpec(
                    name=str(item["name"]),
                    description=str(item.get("description") or ""),
                    input_schema=dict(schema) if isinstance(schema, Mapping) else {},
                    server=server,
                    annotations=dict(annotations) if isinstance(annotations, Mapping) else {},
                    output_schema=dict(out_schema) if isinstance(out_schema, Mapping) else {},
                )
            )

    if isinstance(raw, list):
        _add_tools(raw, "")
    elif isinstance(raw, Mapping):
        top_server = str(raw.get("server") or "").strip()
        if isinstance(raw.get("tools"), list):
            _add_tools(raw["tools"], top_server)
        result_obj = raw.get("result")
        if isinstance(result_obj, Mapping) and isinstance(result_obj.get("tools"), list):
            _add_tools(result_obj["tools"], top_server)
        servers = raw.get("mcpServers") or raw.get("servers")
        if isinstance(servers, Mapping):
            for server_name, cfg in servers.items():
                if not isinstance(cfg, Mapping):
                    continue
                if isinstance(cfg.get("tools"), list):
                    _add_tools(cfg["tools"], str(server_name))
                ref_manifest = cfg.get("manifest") or cfg.get("tools_manifest")
                if isinstance(ref_manifest, str) and ref_manifest.strip():
                    ref_path = (source.parent / ref_manifest).resolve()
                    try:
                        ref_path.relative_to(base_dir)
                    except ValueError as exc:
                        raise ValueError(
                            f"MCP manifest reference '{ref_manifest}' escapes base directory '{base_dir}'"
                        ) from exc
                    for sub in load_mcp_manifest(
                        ref_path, _visited=next_visited, _base_dir=base_dir
                    ):
                        specs.append(
                            MCPToolSpec(
                                name=sub.name,
                                description=sub.description,
                                input_schema=sub.input_schema,
                                server=sub.server or str(server_name),
                                annotations=sub.annotations,
                                output_schema=sub.output_schema,
                            )
                        )
    else:
        raise ValueError(f"Unsupported MCP manifest JSON structure in {source}")

    return specs


def compute_tool_pins(tools: Sequence[MCPToolSpec]) -> dict[str, str]:
    """Return a deterministic mapping of qualified MCP tool names to SHA-256 hashes."""
    return {tool.qualified_name: tool.canonical_hash() for tool in tools}


def verify_tool_pins(
    tools: Sequence[MCPToolSpec],
    expected_pins: Mapping[str, str],
) -> list[PolicyViolation]:
    """Detect MCP rug-pull mutations, unpinned tool additions, and removed pinned tools."""
    violations: list[PolicyViolation] = []
    seen_keys: set[str] = set()
    for tool in tools:
        key = tool.qualified_name
        seen_keys.add(key)
        observed = tool.canonical_hash()
        if key not in expected_pins:
            violations.append(
                PolicyViolation(
                    rule_id="POL-ASI04-002",
                    rule_name="MCP Tool Rug-Pull Pin Mismatch",
                    owasp_category="ASI04: Agentic Supply Chain Vulnerabilities",
                    severity="CRITICAL",
                    offending_span_id=f"mcp-pin:{key}",
                    offending_step_index=-1,
                    offending_tool_name=key,
                    failure_action="BLOCK_PR",
                    evidence={
                        "reason": "mcp_tool_unpinned_addition",
                        "observed_sha256": observed,
                        "server": tool.server or "default",
                    },
                    remediation=(
                        f"MCP tool '{key}' is not present in the trusted pin file. "
                        "Audit the newly added or renamed tool before updating pins."
                    ),
                )
            )
            continue
        expected = str(expected_pins[key])
        if observed != expected:
            violations.append(
                PolicyViolation(
                    rule_id="POL-ASI04-002",
                    rule_name="MCP Tool Rug-Pull Pin Mismatch",
                    owasp_category="ASI04: Agentic Supply Chain Vulnerabilities",
                    severity="CRITICAL",
                    offending_span_id=f"mcp-pin:{key}",
                    offending_step_index=-1,
                    offending_tool_name=key,
                    failure_action="BLOCK_PR",
                    evidence={
                        "reason": "mcp_tool_pin_mismatch",
                        "expected_sha256": expected,
                        "observed_sha256": observed,
                        "server": tool.server or "default",
                    },
                    remediation=(
                        f"MCP tool '{key}' changed its description or schema since pinning. "
                        "Audit the diff for supply-chain tampering before updating the pin file."
                    ),
                )
            )
    for missing_key in sorted(set(expected_pins.keys()) - seen_keys):
        violations.append(
            PolicyViolation(
                rule_id="POL-ASI04-002",
                rule_name="MCP Tool Rug-Pull Pin Mismatch",
                owasp_category="ASI04: Agentic Supply Chain Vulnerabilities",
                severity="HIGH",
                offending_span_id=f"mcp-pin:{missing_key}",
                offending_step_index=-1,
                offending_tool_name=missing_key,
                failure_action="BLOCK_PR",
                evidence={
                    "reason": "mcp_tool_pin_removed",
                    "expected_sha256": str(expected_pins[missing_key]),
                },
                remediation=(
                    f"Pinned MCP tool '{missing_key}' is missing from the manifest. "
                    "Verify whether the tool was renamed or removed intentionally."
                ),
            )
        )
    return violations


def scan_mcp_tools(
    tools: Sequence[MCPToolSpec],
    *,
    expected_pins: Mapping[str, str] | None = None,
    extra_patterns: Mapping[str, str] | None = None,
    enable_poisoning_scan: bool = True,
) -> EvaluationResult:
    """Run ASI04 tool poisoning, duplicate detection, and optional rug-pull pin verification."""
    started = time.perf_counter()
    violations: list[PolicyViolation] = []

    seen_names: set[str] = set()
    for tool in tools:
        qname = tool.qualified_name
        if qname in seen_names:
            violations.append(
                PolicyViolation(
                    rule_id="POL-ASI04-001",
                    rule_name="Tool Description Poisoning Detection",
                    owasp_category="ASI04: Agentic Supply Chain Vulnerabilities",
                    severity="CRITICAL",
                    offending_span_id=f"tool-def:{qname}",
                    offending_step_index=-1,
                    offending_tool_name=qname,
                    failure_action="BLOCK_PR",
                    evidence={
                        "reason": "duplicate_mcp_tool_name",
                        "tool": qname,
                    },
                    remediation=(
                        f"Remove duplicate MCP tool registration '{qname}' to prevent "
                        "intra-manifest tool shadowing."
                    ),
                )
            )
        seen_names.add(qname)

    if enable_poisoning_scan:
        poison_inputs = [
            {
                "name": tool.qualified_name,
                "description": tool.description,
                "parameter_metadata": tool.parameter_metadata,
            }
            for tool in tools
        ]
        violations.extend(scan_tool_definitions(poison_inputs, extra_patterns=extra_patterns))

    if expected_pins is not None:
        violations.extend(verify_tool_pins(tools, expected_pins))

    elapsed_ms = max(0.01, (time.perf_counter() - started) * 1000.0)
    return EvaluationResult(
        status="FAIL" if violations else "PASS",
        total_spans_evaluated=len(tools),
        violations=violations,
        execution_time_ms=round(elapsed_ms, 3),
    )
