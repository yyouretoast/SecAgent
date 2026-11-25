# SecAgent User Stories & Acceptance Criteria

**Project**: SecAgent (CI/CD Security Gate for Autonomous AI Agents)  
**Definition of Done**: Automated tests pass (`pytest`), linting/formatting pass (`ruff check .`, `ruff format --check .`), type checks pass (`mypy src/secagent`), and schema contracts remain valid.

---

## Epic 1: Agent Introspection, Harness & Privilege SDK (`Student 1`)

### US-1.1: Multi-Strategy Dynamic Tool Introspection
Extract tool names, docstrings, and parameter schemas from `--agent module:app` without manual manifests.
* **Criteria**: Supports LangGraph `CompiledStateGraph` (`tools_by_name`/`tools`), direct tool attributes, getter methods, and module inspection; explicit CLI `--agent` failures fail closed with exit `1` (`on_error="warn"` falls back to baseline tools).
* **Code & Tests**: `src/secagent/harness/introspector.py` (`discover_tools`) · `tests/test_introspector.py`

### US-1.2: Privilege Tier Resolution & SDK Decorator
Annotate tools with `@permission(tier=...)` and resolve tiers deterministically.
* **Criteria**: Preserves wrapped function signatures/metadata; resolves tiers via `@permission` > `tool_tier_overrides` > name heuristic.
* **Code & Tests**: `src/secagent/sdk/decorators.py`, `src/secagent/harness/introspector.py` (`resolve_permission_tier`) · `tests/test_sdk.py`, `tests/test_introspector.py`

### US-1.3: Isolated Dry-Run Sandbox & Virtualized Mock Dispatcher
Mock mutating and network tools during CI scans so tests never cause real side effects.
* **Criteria**: Virtualizes `pay`, `admin`, `write`, and `net` tools to return `{"status": "mock_success", "dry_run": True}` while recording arguments; executes `pure` and `read` tools normally.
* **Code & Tests**: `src/secagent/harness/sandbox.py` · `tests/test_sandbox.py`

### US-1.4: Timeout & Fault-Tolerant Execution Harness
Enforce per-scenario execution timeouts and trap unhandled agent exceptions.
* **Criteria**: Timed-out or crashing runs emit an `agent.run` error span (`is_error: True`) and return control cleanly to the runner.
* **Code & Tests**: `src/secagent/harness/runner.py` · `tests/test_runner.py`

### US-1.5: Reference Agent Fixtures (Finance, DevOps, Support, Multi-Agent Ops)
Provide deterministic, zero-LLM LangGraph fixtures for reproducible CI and demo runs.
* **Criteria**: `finance_agent`, `devops_agent`, `support_agent`, and `multi_agent_ops` each expose compliant `:app` (`PASS`) and insecure `:vulnerable_app` (`FAIL`); `multi_agent_ops` contains deterministic supervisor/worker delegation and shared-tool or memory signals for MAESTRO routing tests.
* **Code & Tests**: `examples/`, `src/secagent/harness/scripted.py`, new `examples/multi_agent_ops.py` · `tests/test_finance_agent.py`, `tests/test_devops_agent.py`, `tests/test_support_agent.py`, new `tests/test_multi_agent_ops.py`

### US-1.6: Context-Aware Threat-Model Topology Classifier
Classify the introspected target immediately after discovery so simple workflows retain the OWASP baseline and complex MAS targets receive MAESTRO analysis.
* **Criteria**: Detects multiple agent nodes, supervisor/delegation graphs, inter-agent handoffs, and shared memory/tools; `auto` selects the existing zero-LLM OWASP baseline for a simple/single-agent fixture and OWASP + MAESTRO for `multi_agent_ops`; an explicit threat-model override takes precedence.
* **Code & Tests**: `src/secagent/harness/introspector.py`, new `src/secagent/harness/topology.py`, new `src/secagent/harness/threat_router.py` · new `tests/test_threat_router.py`

---

## Epic 2: Telemetry Pipeline & PII Redaction (`Student 3`)

### US-2.1: OpenTelemetry GenAI Callback Interceptor
Capture `agent.run`, `model.inference`, and `tool.call` spans from LangChain/LangGraph runs.
* **Criteria**: Records chronological `step_index`, nanosecond timestamps, resolved `permission_tier`, and OpenTelemetry SDK spans.
* **Code & Tests**: `src/secagent/telemetry/callbacks.py` · `tests/test_telemetry.py`

### US-2.2: LangGraph HITL Interrupt Normalizer (`gate.hitl`)
Normalize human approval gates and interrupts into `gate.hitl` trace spans.
* **Criteria**: Preserves `approval_granted` boolean, `operation`, and optional `approver` metadata in chronological session order.
* **Code & Tests**: `src/secagent/telemetry/hitl.py` · `tests/test_telemetry.py`

### US-2.3: Recursive In-Line PII & Secret Redactor
Scrub sensitive credentials and PII before trace serialization.
* **Criteria**: Recursively redacts SSNs, Luhn-valid card numbers, and `sk-` / `ghp_` / `Bearer` tokens across strings, dicts, and lists without altering structure.
* **Code & Tests**: `src/secagent/telemetry/redactor.py` · `tests/test_telemetry.py`

### US-2.4: Trace Exporter & Schema Draft 2020-12 Validation
Validate and export execution traces against `schemas/trace_event.schema.json`.
* **Criteria**: Raises `jsonschema.ValidationError` on malformed traces; passes `Draft202012Validator` on valid runs; preserves compatibility when optional MAESTRO metadata is absent.
* **Code & Tests**: `src/secagent/telemetry/exporter.py` · `tests/test_contracts.py`, `tests/test_telemetry.py`

### US-2.5: MAESTRO Layer-Tagged Telemetry
Expose a non-breaking architectural-layer tag on execution spans for MAS analysis.
* **Criteria**: A span may carry an optional `maestro_layer` from L1-L7; both repository and packaged trace schemas accept it; a trace without the field remains schema-valid and produces the same OWASP policy result.
* **Code & Tests**: `src/secagent/telemetry/callbacks.py`, `src/secagent/telemetry/hitl.py`, `src/secagent/telemetry/exporter.py`, `schemas/trace_event.schema.json`, `src/secagent/schemas/trace_event.schema.json` · `tests/test_telemetry.py`, `tests/test_contracts.py`

---

## Epic 3: Dynamic Scenario Generator & Fuzzer (`Student 2`)

### US-3.1: 8-Category OWASP Attack Vector Synthesizer
Synthesize adversarial scenarios from introspected tool definitions without manual YAML authoring.
* **Criteria**: Generates structured `GeneratedScenario` cases covering 8 OWASP categories: 7 trace-verifiable YAML categories plus the static ASI04 tool-description poisoning check; remains the deterministic baseline scenario source for every route.
* **Code & Tests**: `src/secagent/generator/__init__.py` · `tests/test_contracts.py`

### US-3.2: Schema-Directed Parameter Fuzzing Engine
Inject attack payloads into schema-compatible tool parameters rather than blind dicts.
* **Criteria**: Inspects Pydantic `args_schema` / `inspect.signature`, populates valid defaults for non-target parameters, and injects payloads into matching string fields.
* **Code & Tests**: `src/secagent/generator/fuzzer.py` · `tests/test_generator_fuzzer.py`

### US-3.3: Deterministic Seeding & Test Suite Caching
Cache synthesized scenario suites across unchanged commits.
* **Criteria**: Computes SHA-256 cache keys from tool schemas, overrides, seed, settings, source fingerprints, and selected threat-model/model configuration; invalidates automatically when agent code, tools, or synthesis inputs change.
* **Code & Tests**: `src/secagent/generator/cache.py` · `tests/test_generator_cache.py`

### US-3.4: Native CSA MAESTRO Seven-Layer Adapter
Port CSA MAESTRO's core taxonomy, typed threat-report models, and prompt templates into the Python package without a framework fork or Genkit service.
* **Criteria**: Validates only official L1-L7 layer identifiers; converts introspected schemas, tools, permissions, and graph edges into a structured threat-model request/report; has no runtime dependency on a CSA repository checkout or network microservice.
* **Code & Tests**: new `src/secagent/maestro/taxonomy.py`, `models.py`, `prompts.py`, `adapter.py` · new `tests/test_maestro_adapter.py`

### US-3.5: Two-Step MAESTRO Threat-to-Payload Synthesis
For the multi-agent route only, derive concrete payloads from an architecture-specific MAESTRO threat report and the OWASP baseline.
* **Criteria**: Only `secagent generate` invokes LLMs: on a cache miss or explicit refresh it calls the MAESTRO threat modeler before the payload synthesizer exactly once each for `multi_agent_ops`; the simple OWASP route makes zero LLM calls. `secagent scan` never invokes an LLM: on a missing multi-agent cache, `auto` emits a WARN banner and PR-comment notice, falls back to the deterministic OWASP suite, and exits `1` only for an OWASP `BLOCK_PR` violation; explicit `--threat-model maestro` exits `1` and prints the exact `secagent generate` command required to populate or refresh the cache. The generated suite is cached, remains compatible with the scenario contract, and optional `external_refs`/`atlas_id` are reserved as v2 hooks.
* **Code & Tests**: new `src/secagent/generator/metaprompt.py`, new `schemas/generated_scenario.schema.json`, modified `src/secagent/generator/__init__.py`, `cache.py` · new `tests/test_maestro_synthesis.py`, `tests/test_generator_cache.py`

### US-3.6: CSA MAESTRO Attribution and Prompt Provenance
Record the provenance of the native MAESTRO adaptation before shipping it.
* **Criteria**: `CREDITS.md` or `README.md` links to `https://github.com/CloudSecurityAlliance/MAESTRO`; ported prompt/taxonomy source files contain an attribution comment; documentation identifies the adaptation as native Python rather than a CSA fork.
* **Code & Tests**: `CREDITS.md` or `README.md`, `src/secagent/maestro/` · documentation review checklist

---

## Epic 4: Invariant Policy Verification Engine (`Student 4`)

### US-4.1: Policy Ruleset Loader & Schema Validator
Load and strictly validate `policies/security_rules.yaml`.
* **Criteria**: Rejects unknown fields, invalid regexes, duplicate IDs, and unsupported `rule_type` values via Pydantic `PolicyLoadError`; accepts documented optional MAESTRO layer/cross-layer selectors and nullable future external references without weakening validation of current OWASP rules.
* **Code & Tests**: `src/secagent/engine/loader.py` · `tests/test_engine_loader.py`

### US-4.2: Predecessor HITL Gate Enforcement Verifier (POL-ASI03-001)
Require `pay` and `admin` tool calls to follow an unconsumed, approved `gate.hitl` span.
* **Criteria**: Flags missing, denied, errored, already-consumed, or operation-mismatched gates within `max_lookback_operational_steps`.
* **Code & Tests**: `src/secagent/engine/rules/predecessor_gate.py` · `tests/test_us4_2_predecessor_gate.py`

### US-4.3: Context Privilege Boundary Enforcement Verifier (POL-ASI03-002)
Forbid mutating, payment, admin, or network tools during read-only `task_context` sessions.
* **Criteria**: Flags any `tool.call` matching `forbidden_tiers` or `forbidden_tools` under the restricted context.
* **Code & Tests**: `src/secagent/engine/rules/context_privilege.py` · `tests/test_us4_3_context_privilege.py`

### US-4.4: Parameter Injection Regex Blocklist Verifier (POL-ASI02-001, POL-ASI05-001)
Detect SQL injection and shell command injection patterns in tool input parameters.
* **Criteria**: Recursively scans string values inside `input_parameters` for scoped tools/tiers and reports exact parameter path and matched pattern.
* **Code & Tests**: `src/secagent/engine/rules/parameter_regex.py` · `tests/test_us4_4_parameter_regex.py`

### US-4.5: Need-to-Know Field Scope Allowlist Verifier (POL-ASI06-001)
Block sensitive PII/credential fields (`ssn`, `salary`, `password_hash`, etc.) in scoped database queries.
* **Criteria**: Inspects configured `input_parameters`, `output_result`, and `attributes` under matching `task_context`.
* **Code & Tests**: `src/secagent/engine/rules/field_scope.py` · `tests/test_us4_5_field_scope.py`

### US-4.6: Runaway Execution & Circuit Breaker Verifier (POL-ASI08-001)
Enforce total operational step limits and consecutive identical tool-call thresholds.
* **Criteria**: Flags traces exceeding `max_total_steps` or `max_consecutive_identical_tools`.
* **Code & Tests**: `src/secagent/engine/rules/circuit_breaker.py` · `tests/test_us4_6_circuit_breaker.py`

### US-4.7: Network Egress Allowlist Verifier (POL-ASI10-001)
Restrict `net`-tier tool destinations to approved domains and block known exfiltration sinks.
* **Criteria**: Extracts URLs and destination hostnames safely, flags forbidden patterns and non-allowlisted domains, and handles malformed URLs gracefully.
* **Code & Tests**: `src/secagent/engine/rules/network_egress.py` · `tests/test_us4_7_network_egress.py`

### US-4.8: Structured Violation Record & Remediation Generator
Format policy evaluation results into JSON audit reports and SARIF 2.1.0 documents.
* **Criteria**: Emits `report.json` with trace/scenario summaries and valid SARIF 2.1.0 (`generate_sarif`) for GitHub Code Scanning.
* **Code & Tests**: `src/secagent/engine/reporter.py` · `tests/test_us4_8_engine_reporter.py`, `tests/test_reporting.py`

### US-4.9: MAESTRO Layer-Aware and Cross-Layer Policy Rules
Evaluate optional MAS policies that reason about architectural layers without changing existing OWASP semantics.
* **Criteria**: `cross_layer_flow.py` evaluates only traces carrying explicit `maestro_layer` tags and supports a layer-scoped rule plus a cross-layer flow rule that blocks an unvalidated L7/L2 source reaching a high-privilege destination unless an L6 control is present; it does not duplicate or alter the tier-based `ToxicFlowRule` (`POL-ASI01-002`); existing `security_rules.yaml` loads and its current fixture verdicts are unchanged; optional `external_refs: []` and `atlas_id: null` validate as v2 hooks only.
* **Code & Tests**: `src/secagent/engine/loader.py`, `evaluator.py`, `reporter.py`, new `src/secagent/engine/rules/cross_layer_flow.py`, `policies/security_rules.yaml` · new `tests/test_maestro_policy_rules.py`, `tests/test_engine_loader.py`

---

## Epic 5: CLI, GitHub Action & Audit Dashboard (`Student 5`)

### US-5.1: CLI `scan` Command Pipeline Orchestration
Orchestrate introspection, scenario synthesis/loading, sandboxed execution, and policy evaluation via `secagent scan`.
* **Criteria**: Supports `--agent`, `--trace`, `--scenarios`, `--timeout`, `--output-sarif`, `--quiet`, `--json`, and `--threat-model auto|owasp|maestro` (default `auto`); `secagent scan` never invokes an LLM under any flag; on a multi-agent cache miss, `auto` emits a WARN banner/PR notice and falls back to the deterministic OWASP suite, while explicit `maestro` fails closed with exit `1` and prints the exact generate command; exits `1` on `BLOCK_PR` violations and `0` on `PASS`.
* **Code & Tests**: `src/secagent/cli.py`, `src/secagent/ui.py` · `tests/test_cli_scan_telemetry.py`, `tests/test_ui.py`

### US-5.2: GitHub Action Composite Runner (`action.yml`)
Gate pull requests automatically in GitHub Actions.
* **Criteria**: Runs `secagent scan`, writes `$GITHUB_STEP_SUMMARY`, posts sticky PR comments, and exits `1` unless status is `PASS` or `WARN`.
* **Code & Tests**: `action.yml`, `.github/workflows/secagent-ci.yml` · `tests/test_action.py`

### US-5.3: Automated Pull Request Triage Comment Formatter (`comment.md`)
Format evaluation results into a concise Markdown table with collapsible evidence for PRs.
* **Criteria**: Sorts findings by severity, escapes Markdown/HTML characters, respects GitHub's 65KB comment limit, and includes `<!-- secagent-security-gate -->` marker.
* **Code & Tests**: `src/secagent/cli.py` (`_format_markdown_report`) · `tests/test_reporting.py`

### US-5.4: Standalone Scenario Generation & Fuzzing CLI Commands
Expose `secagent generate` and `secagent fuzz` (with `--execute`) for local and scheduled testing.
* **Criteria**: Writes sanitized JSON scenario manifests to `--output-dir` and optionally executes fuzzed suites against the policy engine.
* **Code & Tests**: `src/secagent/cli.py` · `tests/test_cli_generate_fuzz.py`

### US-5.5: Interactive Streamlit Audit Dashboard (`app.py`)
Provide a local web UI for inspecting trace waterfalls, OWASP breakdowns, and `--baseline` regression diffs.
* **Criteria**: Launched via `secagent serve` bound to `127.0.0.1`; renders trace timelines, span details, and new/resolved/unchanged diffs against a baseline report.
* **Code & Tests**: `src/secagent/app.py` · `tests/test_dashboard.py`

### US-5.6: Threat-Model CLI Configuration and Route Reporting
Make the selected route and independently configured MAESTRO/payload models observable and reproducible from the CLI.
* **Criteria**: `auto`, `owasp`, and `maestro` values are validated; the report records the selected route; MAESTRO and payload model settings are independent for `secagent generate`; omitted settings retain zero-LLM OWASP-only routing semantics for simple fixtures; `secagent scan` never invokes an LLM and consumes cached scenarios, warning/falling back or failing closed according to the multi-agent cache-miss rule.
* **Code & Tests**: `src/secagent/cli.py`, `src/secagent/ui.py`, `src/secagent/app.py` · new `tests/test_cli_threat_model.py`
