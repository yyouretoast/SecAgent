# SecAgent Implementation Plan

* **Target**: DEPI Agentic AI Track Capstone (5-week delivery, 5 engineers)
* **Stack**: Python 3.11+, LangGraph, OpenTelemetry SDK, Pydantic v2, Typer, Rich, Streamlit
* **Architecture & Overview**: [RFC-001](RFC-001-architecture.md) · [README](../README.md)

---

## 1. Design Constraints

1. **Deterministic CI Gate**: Policy evaluation runs on structured execution traces in memory without LLM-as-a-judge calls, keeping PR checks fast, free, and reproducible.
2. **Dry-Run Safety**: Mutating/external tool tiers (`pay`, `admin`, `write`, `net`) are virtualized during scans so CI runs never trigger real payments, host commands, or outbound HTTP requests.
3. **Frozen Contracts**: Cross-team integration relies on two shared schemas:
   - `schemas/trace_event.schema.json` (JSON Schema Draft 2020-12)
   - `policies/security_rules.yaml` (declarative OWASP rule bundle)
4. **Defense in Depth**: OWASP Top 10 for Agentic AI remains the deterministic baseline and the source of standard vulnerability IDs. CSA MAESTRO complements it for multi-agent-system (MAS) topology, trust-boundary, and cross-layer threat analysis; it does not replace OWASP coverage.
5. **Deterministic Verdicts**: Optional model calls may synthesize threat reports and test payloads, but the CI verdict remains the existing deterministic policy evaluation over traces. Generated suites remain cacheable and reviewable before execution.

---

## 2. Subsystem & Module Map

```text
src/secagent/
├── agent/state.py          # Shared LangGraph AgentState TypedDict
├── sdk/decorators.py       # @permission(tier=...) metadata decorator
├── harness/
│   ├── introspector.py     # Multi-strategy tool discovery & tier resolution
│   ├── sandbox.py          # VirtualizedToolWrapper for dry-run mocking
│   ├── runner.py           # ExecutionHarness with thread/async timeout isolation
│   └── scripted.py         # Deterministic zero-LLM reference graph builder
├── telemetry/
│   ├── callbacks.py        # SecAgentTelemetryCallback + OTelRuntime spans
│   ├── hitl.py             # HITLNormalizer for gate.hitl interrupt spans
│   ├── redactor.py         # PIIRedactor (SSN, Luhn cards, API/Bearer tokens)
│   └── exporter.py         # Draft 2020-12 trace schema validator & JSON writer
├── generator/
│   ├── __init__.py         # ScenarioGenerator & ToolMetadata
│   ├── fuzzer.py           # SchemaDirectedFuzzer for typed parameter injection
│   └── cache.py            # SHA-256 ScenarioCache + source fingerprinting
├── engine/
│   ├── loader.py           # Strict Pydantic PolicyLoader for security_rules.yaml
│   ├── evaluator.py        # PolicyEngine + tool_tier_overrides resolution
│   ├── reporter.py         # PolicyReporter (JSON summary + SARIF 2.1.0)
│   └── rules/              # 8 rule evaluators + ASI04 tool-poisoning scanner
├── schemas/                # Packaged trace_event.schema.json
├── cli.py                  # Typer CLI (scan, test, generate, fuzz, serve)
├── ui.py                   # Rich terminal header, violation cards & summary
└── app.py                  # Streamlit waterfall & --baseline diff dashboard
```

---

### 2.1 MAESTRO Module Delta

| Status | Planned modules |
| :--- | :--- |
| **Modified** | `harness/introspector.py`, `generator/__init__.py`, `generator/cache.py`, `telemetry/callbacks.py`, `telemetry/hitl.py`, `telemetry/exporter.py`, `engine/loader.py`, `engine/evaluator.py`, `engine/reporter.py`, `cli.py`, `ui.py`, `app.py`, `schemas/trace_event.schema.json`, `src/secagent/schemas/trace_event.schema.json`, and `policies/security_rules.yaml` |
| **New** | `harness/topology.py`, `harness/threat_router.py`, `generator/metaprompt.py`, `maestro/__init__.py`, `maestro/taxonomy.py`, `maestro/models.py`, `maestro/prompts.py`, `maestro/adapter.py`, `engine/rules/cross_layer_flow.py`, `examples/multi_agent_ops.py`, `CREDITS.md`, `schemas/generated_scenario.schema.json`, packaged `src/secagent/schemas/generated_scenario.schema.json`, and focused router/adapter/chain regression tests |

## 3. Subsystem Responsibilities

### 3.1 Introspection, Harness & SDK (`harness/`, `sdk/`, `examples/`)
* Discover tools from LangGraph `CompiledStateGraph` nodes, `tools` attributes, getter methods, or module members.
* Resolve privilege tiers in strict precedence: `@permission` decorator > `tool_tier_overrides` in policy YAML > name heuristic (`pay` → `admin` → `write` → `net` → `pure` → `read`).
* Wrap `pay`/`admin`/`write`/`net` tools in `VirtualizedToolWrapper` returning `{"status": "mock_success", "dry_run": True}` and enforce per-scenario timeouts (`DEFAULT_TIMEOUT_S = 5.0`) in `ExecutionHarness`.
* Provide four deterministic, zero-LLM reference agents in `examples/`: `finance_agent`, `devops_agent`, `support_agent`, and `multi_agent_ops`. Each exports a compliant `:app` and insecure `:vulnerable_app`; `multi_agent_ops` additionally exercises supervisor/worker delegation, shared tools or memory, and cross-layer data flow.
* **MAESTRO extension (modified `introspector.py`, new `topology.py` and `threat_router.py`)**: Produce a topology profile immediately after tool introspection. It classifies a target as simple/single-agent or complex/multi-agent using observable signals: multiple agent nodes, supervisor/delegation graphs, inter-agent handoffs, or shared memory/tools. The profile is input to threat-model routing; it does not alter privilege-tier resolution or sandbox behavior.

### 3.2 Telemetry & Redaction (`telemetry/`)
* Capture `agent.run`, `model.inference`, `tool.call`, and `gate.hitl` spans via `SecAgentTelemetryCallback` and emit OpenTelemetry SDK spans via `OTelRuntime`.
* Normalize LangGraph `approval_gate` / `__interrupt__` events into `gate.hitl` spans with `approval_granted`.
* Scrub SSNs, Luhn-validated card numbers, and `sk-` / `ghp_` / `Bearer` tokens recursively via `PIIRedactor` before trace validation.
* **MAESTRO extension (modified `callbacks.py`, `hitl.py`, `exporter.py`, and both trace-schema copies)**: Add an optional `maestro_layer` span attribute. It is additive and uses only the official taxonomy below, so existing traces and OWASP evaluators remain valid. The repository schema and packaged `src/secagent/schemas/` copy must change together.

### 3.3 Scenario Generator & Fuzzer (`generator/`)
* Synthesize OWASP-mapped scenarios from introspected tool schemas and inject payloads into compatible string parameters via `SchemaDirectedFuzzer`.
* Cache generated suites under `scenarios/.cache/` keyed by tool signatures, policy overrides, seed, settings, and AST/source fingerprint.
* **Context-aware threat-model routing (new `harness/threat_router.py`)**: `auto` is the default. A simple/single-agent topology takes the existing deterministic OWASP baseline path and makes zero LLM calls. A complex/multi-agent topology takes the OWASP + MAESTRO path. The CLI may force `owasp` or `maestro` for reproducible generation investigations.
* **Multi-agent synthesis chain (new `generator/metaprompt.py`, new `maestro/`)**: Only the MAESTRO multi-agent route performs two distinct model calls inside `secagent generate`, on a cache miss or explicit refresh: (1) a MAESTRO threat modeler maps the introspected topology, schemas, tools, permissions, and graph edges into a structured seven-layer threat report; (2) the payload synthesizer receives that report plus the OWASP baseline and produces concrete JSON fuzzing payloads. Each step has independent model configuration, allowing a stronger reasoning model for step 1 and a lower-cost model for step 2. The generated suite is persisted by `ScenarioCache`.
* **Zero-LLM scan boundary**: `secagent scan` never invokes an LLM, regardless of `--threat-model`. If a multi-agent cache entry is missing, `auto` emits a `WARN` banner and PR-comment notice, falls back to the deterministic OWASP baseline suite, and exits `1` only when OWASP finds a `BLOCK_PR` violation. Explicit `--threat-model maestro` fails closed with exit `1` and prints the exact `secagent generate` command needed to populate or refresh the cache.
* **Native adapter boundary**: The implementation ports the MAESTRO taxonomy, Pydantic models, and prompt templates into native Python. It must not fork `CloudSecurityAlliance/MAESTRO` or run its Genkit stack as a microservice. The adapter's structured-output contract is the only provider-facing boundary.

### 3.4 Policy Engine & Reporting (`engine/`)
* Validate `policies/security_rules.yaml` with strict Pydantic models (`PolicyLoader`).
* Evaluate traces deterministically across 7 YAML rule categories (`POL-ASI01-001/002`, `POL-ASI02-001`, `POL-ASI03-001/002`, `POL-ASI05-001`, `POL-ASI06-001`, `POL-ASI08-001`, `POL-ASI10-001`) plus static tool-description poisoning (`POL-ASI04-001`).
* Export structured JSON reports and SARIF 2.1.0 documents (`PolicyReporter`).
* **MAESTRO extension (modified `loader.py`, `evaluator.py`, `reporter.py`; new `rules/cross_layer_flow.py`)**: Support optional layer-aware and cross-layer policy selectors without changing the semantics of existing OWASP YAML policies. `cross_layer_flow.py` evaluates only traces carrying explicit `maestro_layer` tags. It does not duplicate or alter the existing tier-based `ToxicFlowRule` (`POL-ASI01-002`). A policy can constrain a MAESTRO layer or require an L6 security/compliance control between a source layer and a privileged destination. Example: block unvalidated L7 external input or L2 untrusted data flowing to a high-privilege tool unless an L6 guardrail/HITL gate intervenes.
* **v2 compatibility hook**: Add a generated-scenario JSON Schema (the current `GeneratedScenario` dataclass has no standalone JSON Schema) and extend YAML policy models to reserve nullable optional external references (`external_refs: list[str] = []` and/or `atlas_id: null`) for future MITRE ATLAS mappings. MITRE ATLAS analysis is explicitly out of scope for v1.

### 3.5 CLI, GitHub Action & Dashboard (`cli.py`, `ui.py`, `app.py`, `action.yml`)
* Orchestrate `scan` (dynamic or `--trace`), `generate`, `fuzz --execute`, and `serve --baseline`.
* Gate pull requests via `action.yml`: exit `1` on `BLOCK_PR` violations, post sticky PR triage comments (`comment.md`), write `$GITHUB_STEP_SUMMARY`, and emit SARIF for GitHub Code Scanning.
* Render trace waterfalls, OWASP charts, and `--baseline` regression diffs locally in Streamlit.
* **MAESTRO extension (modified `cli.py`, `ui.py`, and dashboard/report views as required)**: Expose `--threat-model auto|owasp|maestro` (default `auto`) and independent MAESTRO-model/payload-model configuration for `secagent generate`. Reports retain OWASP identifiers and may add route, MAESTRO-layer, and cross-layer evidence fields without changing existing output consumers. `secagent scan` never makes LLM calls; its cache-miss behavior follows the zero-LLM scan boundary above.

### 3.6 CSA MAESTRO Taxonomy, Attribution & Boundaries

The native adapter uses these CSA MAESTRO layers exactly:

| Layer | Scope in SecAgent |
| :--- | :--- |
| **L1: Foundation Models** | LLMs and model APIs |
| **L2: Data Operations** | Databases, vector stores, RAG, memory, and context |
| **L3: Agent Frameworks** | Orchestration, planning, graph execution, and tool frameworks |
| **L4: Deployment & Infrastructure** | Runtime environments, containers, and networks |
| **L5: Evaluation & Observability** | Telemetry, tracing, and audit logs |
| **L6: Security & Compliance** | IAM, `@permission`, guardrails, HITL gates, and YAML policy enforcement |
| **L7: Agent Ecosystem** | Inter-agent protocols, external tools/APIs, and human-agent interfaces |

Prompt templates and any adapted taxonomy/model content must carry source comments and an attribution entry in `CREDITS.md` or the README linking to <https://github.com/CloudSecurityAlliance/MAESTRO>. Attribution is required before the native port is released.

---

## 4. 5-Week Delivery Milestones

| Week | Milestone | Gate |
| :--- | :--- | :--- |
| **Week 1** | Subsystem scaffolding & isolated unit logic | Unit tests pass per module |
| **Week 2** | Harness + Telemetry integration | Agent runs emit valid `trace_event.schema.json` traces |
| **Week 3** | Generator + Policy Engine integration | Engine flags violating traces with exit `1` |
| **Week 4** | CLI, GitHub Action & Streamlit dashboard | End-to-end `secagent scan` & `secagent serve` working |
| **Week 5** | Multi-agent evaluation, hardening & defense | Full `pytest`, `ruff`, `mypy src/secagent` green on `main` |

### 4.1 MAESTRO Integration Workstream (after the current baseline)

| Order | Scope | Modules | Acceptance gate |
| :--- | :--- | :--- | :--- |
| **1** | Topology profile and route decision | Modify `harness/introspector.py`; add `harness/topology.py`, `harness/threat_router.py`; add `examples/multi_agent_ops.py` | Single-agent fixtures choose the deterministic OWASP-only path with zero LLM calls; `multi_agent_ops` chooses the MAESTRO path in `auto`; explicit CLI overrides win. |
| **2** | Native seven-layer adapter | Add `maestro/taxonomy.py`, `models.py`, `prompts.py`, `adapter.py` | Structured output validates against Pydantic models; taxonomy accepts only L1-L7; attribution is present. |
| **3** | Two-step synthesis path | Add `generator/metaprompt.py`; modify `generator/__init__.py`, cache, and CLI | Only `secagent generate` (cache miss or explicit refresh) calls MAESTRO modeling before payload synthesis; each model configuration is independently selectable; generated payloads are cached and remain schema-valid. `secagent scan` never calls an LLM: `auto` warns and falls back to OWASP on a missing multi-agent cache, while explicit `maestro` fails closed and prints the required generate command. |
| **4** | Trace and policy contracts | Modify telemetry modules, both trace schemas, `engine/loader.py`, evaluator/reporter, and policy YAML | `maestro_layer` is optional; existing OWASP traces/policies still validate unchanged; cross-layer L6-gate rule is covered. |
| **5** | End-to-end regression and documentation | Modify CLI/UI/reporting docs as needed | Tests prove the routing matrix, ordered two-step chain, schema compatibility, and unchanged OWASP fixture verdicts. |

### 4.2 Required Integration and Regression Tests

* Unit-test topology classification and `auto`, `owasp`, and `maestro` route selection, including the precedence of an explicit CLI override.
* Use the deterministic single-agent and `multi_agent_ops` fixtures with a fake model provider to prove that the OWASP route makes zero model calls, generation invokes the MAESTRO modeler before the payload synthesizer exactly once each, and repeated generation reuses `ScenarioCache`.
* Test `secagent scan` on a multi-agent cache miss under `auto`: verify the WARN banner/comment, deterministic OWASP fallback, and exit code based only on OWASP `BLOCK_PR` findings.
* Test `secagent scan --threat-model maestro` on a multi-agent cache miss: verify exit code `1`, zero model calls, and an actionable exact `secagent generate` command in the output.
* Validate MAESTRO threat reports, generated payload metadata, YAML policies, and traces containing `maestro_layer` against their contracts.
* Re-run all existing OWASP scenario, policy-engine, telemetry, CLI, and fixture tests to prove zero regression. Existing OWASP YAML and trace documents must load without a MAESTRO field.
