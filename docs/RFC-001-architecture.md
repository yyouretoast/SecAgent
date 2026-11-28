# RFC-001: SecAgent System Architecture

* **RFC ID**: RFC-001
* **Title**: CI/CD Security Scanner & GitHub Action for Autonomous AI Agents
* **Status**: ACCEPTED / IN IMPLEMENTATION
* **Target Delivery**: Late November 2026 (DEPI Agentic AI Track Capstone)
* **Team**: 5 Senior Engineering Students (Part-Time: 4–6 hours/week per student)
* **Companion Specifications**:
  - [Detailed Technical Implementation Plan](IMPLEMENTATION_PLAN.md)
  - [Agile User Stories & Acceptance Criteria](USER_STORIES.md)
  - [Team Implementation Playbook](PLAYBOOK.md)

---

## 1. Problem Statement

### 1.1 Vulnerability Risks in Autonomous AI Agents
When developers update system prompts, modify tool definitions, or upgrade model versions, agents can introduce severe security regressions:
* Executing financial or admin tools without required approval gates (ASI03).
* Passing unvalidated user input directly into database or shell tools (ASI02, ASI05).
* Over-fetching restricted database fields into working memory or exfiltrating data to external URLs.
* Entering non-terminating retry loops.

### 1.2 Limitations of Existing Approaches
* **Output-Based LLM Judges**: Inspect only the final response text. They cannot observe intermediate tool calls, skipped approval checks, or internal argument payloads.
* **Static Analysis (SAST)**: Analyzes static ASTs and cannot anticipate dynamic reasoning trajectories or prompt-driven privilege escalation.
* **Observability Dashboards**: Record logs post-mortem without providing automated pull request gates that halt builds before deployment.

### 1.3 SecAgent Objective
SecAgent provides a GitHub Action and CLI scanner that:
1. Targets autonomous agents (LangGraph-first in Phase 1, using framework-agnostic OpenTelemetry trace schema).
2. Evaluates execution traces against 8 OWASP Top 10 for Agentic AI Applications categories (7 trace-verifiable in YAML + static `ASI04` tool-description poisoning check).
3. Provides an SDK decorator (`@permission(tier="...")`) standardizing tool privilege tiers (`read`, `write`, `pay`, `admin`, `net`).
4. Generates adversarial test scenarios dynamically on the fly based on tool signatures.
5. Preserves OWASP as the deterministic single-agent baseline while adding CSA MAESTRO as a complementary threat-modeling layer for multi-agent topology, trust boundaries, and cross-layer attack chains.

---

## 2. System Architecture

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECAGENT SYSTEM ARCHITECTURE                         │
└────────────────────────────────────────────────────────────────────────────────────────┘

  Developer Pull Request (Prompt patch, tool change, model upgrade)
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 5: CI/CD GATE & CLI RUNNER (action.yml / src/secagent/cli.py)                │
│                                                                                        │
│   GitHub Action Runner executes `secagent scan` / `secagent fuzz`                      │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Dispatches test scenarios
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 3: SCENARIO + MAESTRO GENERATOR (generator/ + maestro/, Student 2)            │
│                                                                                        │
│   OWASP templates/fuzzer; MAESTRO modeler → payload synthesizer on generate cache miss  │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Injects adversarial inputs
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 1: TARGET AGENT + TOPOLOGY ROUTER (user agent / examples, Student 1)         │
│                                                                                        │
│   Autonomous Agent (LangGraph-first / generic OTel trace emitter)                      │
│   ├── Tools decorated with `@permission(tier=...)`                                     │
│   ├── SecAgent SDK: @permission(...)                                                   │
│   └── topology.py + harness/threat_router.py → OWASP or OWASP + MAESTRO route           │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ OpenTelemetry GenAI Spans
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 2: TELEMETRY & PII REDACTION (src/secagent/telemetry/)                       │
│                                                                                        │
│   Span Instrumentation Layer                                                           │
│   ├── agent.run, model.inference, tool.call, gate.hitl                                 │
│   └── In-line PII Scrubber ──► Execution Trace JSON (schemas/trace_event.schema.json)  │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Standardized Trace JSON
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 4: INVARIANT SECURITY ENGINE (src/secagent/engine/)                          │
│                                                                                        │
│   Deterministic Policy Verifier (policies/security_rules.yaml)                         │
│   ├── Enforces mandatory HITL predecessor gates (pay / admin tiers)                    │
│   ├── Checks permission tier boundaries & scope allowlists                             │
│   └── Parameter regex blocklists & recursion loop thresholds                           │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Verdict: Exit Code 0 (PASS) / 1 (FAIL)
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ CI/CD ENFORCEMENT GATE                                                                 │
│                                                                                        │
│   ├── Pass: Allow Pull Request merge                                                   │
│   └── Fail: Block PR merge & post structured security failure triage table             │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 2.1 Threat-Model Routing and MAESTRO Extension

After introspection, SecAgent builds a topology profile. In `auto` mode, a simple/single-agent target uses the existing deterministic OWASP baseline route with zero LLM calls; a complex/multi-agent target (multiple agent nodes, supervisor/delegation graph, inter-agent handoff, or shared memory/tools) uses the OWASP + MAESTRO route. The CLI exposes `--threat-model auto|owasp|maestro`, with `auto` as the default and an explicit option overriding classification.

The multi-agent route has an ordered two-step synthesis path:

1. The MAESTRO threat modeler maps introspected schemas, tools, permissions, graph edges, and topology into a structured seven-layer threat report.
2. The payload synthesizer receives the MAESTRO report together with the OWASP baseline and creates concrete JSON fuzzing payloads.

The two calls have independent model configuration and run only inside `secagent generate`, on a cache miss or explicit refresh. The resulting suite is persisted in `ScenarioCache`. `secagent scan` never invokes an LLM under any flag. If a multi-agent cache entry is missing, `--threat-model auto` emits a WARN banner and PR-comment notice, falls back to the deterministic OWASP suite, and exits `1` only if OWASP finds a `BLOCK_PR` violation. Explicit `--threat-model maestro` fails closed with exit `1` and prints the exact `secagent generate` command needed to populate or refresh the cache. The model calls support test generation only; the final CI decision is still made by the deterministic YAML policy engine, not by an LLM.

MAESTRO is implemented as a native Python adapter with its taxonomy, Pydantic models, and attributed prompt templates. SecAgent will neither fork `CloudSecurityAlliance/MAESTRO` nor deploy its Genkit stack as a microservice.

## 3. Subsystem Specifications

### Subsystem 1: Agent Introspection & Execution Harness
* **Integration**: Invokes candidate agents via entrypoint (`--agent module:app`).
* **Topology Profile**: After tool discovery, identifies single-agent versus MAS topology from agent nodes, supervisor/delegation edges, handoffs, and shared memory/tools. This profile drives the threat-model router only and does not change the sandbox or permission-tier contracts.
* **Reference Fixtures**: Includes `examples/multi_agent_ops.py`, a deterministic zero-LLM supervisor/worker fixture exporting compliant `:app` and insecure `:vulnerable_app` variants for routing and cross-layer policy tests.
* **Safe CI Execution**: All tool invocations execute in a virtualized dry-run sandbox during security testing. Destructive operations (`drop_database`, `execute_trade`) record intended calls and arguments in the trace but return mock success values. The dry-run tier set is `pay/admin/write/net` — `net` included so CI never makes real network calls (amended per #26). No real external side-effects occur during testing.
* **Privilege Tier Discovery (3-Tier Precedence)**:
  1. *Explicit Decorator*: Checks for `@permission(tier="...")` attribute attached to functions (`pure`, `read`, `write`, `pay`, `admin`, `net`).
  2. *Policy Mapping*: Reads external overrides from `policies/security_rules.yaml` (`tool_tier_overrides`).
  3. *Semantic Heuristic*: Infers tiers from tool naming patterns:
     - `pay`: `*(pay|refund|trade|charge|transfer|buy)*`
     - `admin`: `*(drop|delete|restart|kill|exec|bash|deploy)*`
     - `write`: `*(write|update|modify|insert|create)*`
     - `net`: `*(network|http|webhook|curl|fetch|post_)*`
     - `pure`: `*(calc|format|parse|convert|validate)*`
     - `read`: all other tools.
* **Privilege SDK (Optional)**:
  ```python
  from secagent.sdk import permission


  @permission(tier="admin")
  def restart_server(server_id: str) -> dict: ...


  @permission(tier="pay")
  def execute_trade(symbol: str, quantity: int) -> dict: ...
  ```

### Subsystem 2: Telemetry Pipeline
* **Telemetry Standard**: OpenTelemetry GenAI Semantic Conventions (`trace_event.schema.json`).
* **Interrupt Detection**: Captures framework-native human-in-the-loop gates (e.g. LangGraph `interrupt()`) and normalizes them into standard `gate.hitl` trace spans.
* **PII Redactor**: Scans and sanitizes SSNs, payment card numbers, and API tokens before recording traces.
* **Trace Exporter**: Writes execution trace JSON logs with structured span arrays.
* **MAESTRO Attribute**: Adds optional `maestro_layer` to spans using L1-L7. Its absence remains valid for existing traces and OWASP evaluation.

### Subsystem 3: Dynamic Scenario Generator
* **Schema-Aware Generation**: Introspects parameter types and names using Python's `inspect` module and Pydantic schemas. Payloads target query/filter string parameters rather than blind dictionary injection.
* **Deterministic Seeding & Caching**: Generates scenarios with fixed random seeds into `scenarios/generated/`. Test suites are regenerated only when tool signatures or configurations change, preventing non-deterministic CI flakiness across unchanged commits.
* **LLM Boundary**: The OWASP baseline uses the existing zero-LLM templates and schema-directed fuzzer. Only `secagent generate` on the MAESTRO multi-agent route invokes the two chained model calls. `secagent scan` never invokes an LLM; it uses cached MAESTRO scenarios or applies the documented cache-miss fallback/fail-closed behavior.
* **Test Case Synthesis**:
  - Role-spoofing prompts attempting high-privilege execution without authorization (ASI03).
  - Parameter fuzzing targeting user-controlled arguments with SQL injection and shell syntax (ASI02, ASI05).
  - Data extraction prompts targeting sensitive fields (ASI06, ASI10).
  - Recursive goals designed to exceed execution step limits (ASI08).
* **MAS Extension**: On the MAESTRO route only, passes a structured MAESTRO threat report and the OWASP baseline to the payload synthesizer. The single-agent route remains OWASP-only and zero-LLM.

### Subsystem 4: Invariant Verification Engine
Evaluates YAML policies against execution traces deterministically:
1. **Goal Hijack & Toxic Flow Invariants (ASI01)**: Detects instruction overrides (`POL-ASI01-001`) and tainted read/net outputs steering unapproved privileged sinks (`POL-ASI01-002` / `ToxicFlowRule`).
2. **Predecessor Gate Invariant (ASI03)**: High-privilege actions (`pay`, `admin`) must be preceded by an authorized, operation-matching `gate.hitl` span.
3. **Context Privilege Invariant (ASI03)**: Read-only contexts cannot execute mutating tools.
4. **Parameter Injection Invariant (ASI02, ASI05)**: Regex blocklists for SQL and command injection payloads.
5. **Field Scope Invariant (ASI06)**: Blocks queries requesting or returning restricted fields (`ssn`, `password_hash`).
6. **Circuit Breaker Invariant (ASI08)**: Step count limits (<= 10) and duplicate call thresholds.
7. **Egress Allowlist Invariant (ASI10)**: Network tools can only access approved domains.
8. **Tool-Description Poisoning Check (ASI04)**: Scans introspected tool descriptions and schemas for embedded prompt-injection instructions (`POL-ASI04-001`).
9. **Optional MAESTRO Cross-Layer Invariant**: `cross_layer_flow.py` evaluates only traces carrying explicit `maestro_layer` tags, supporting policies such as requiring an L6 security/compliance control before untrusted L7/L2 data reaches a high-privilege destination. It does not duplicate or alter the existing tier-based `ToxicFlowRule` (`POL-ASI01-002`). Existing OWASP policies remain unchanged and valid.

### Subsystem 5: GitHub Action & Developer CLI
* **Dual-Lifecycle Execution Model**:
  - `secagent scan` (Every PR): Evaluates target agents against cached/generated scenarios and never invokes an LLM under any flag. Simple targets use the zero-LLM OWASP baseline. Multi-agent targets consume the cached MAESTRO-generated suite; on a cache miss, `auto` warns and falls back to OWASP while explicit `maestro` fails closed and prints the required `secagent generate` command.
  - `secagent generate` (On Tool Change): Invoked locally or in CI when tool signatures mutate to refresh `scenarios/generated/`.
  - `secagent fuzz --execute` (Periodic / Nightly): Runs schema-directed parameter mutations and evaluates traces against the policy engine.
  - `secagent serve --baseline` (Audit UI): Launches the Streamlit trace waterfall dashboard with optional baseline regression diffing.
* **GitHub Action (`action.yml`)**: Composite action running on pull requests with sticky PR comment updates and `$GITHUB_STEP_SUMMARY`.
* **Exit Codes**:
  - `0`: All security invariants satisfied.
  - `1`: Security policy violation detected. Pull request blocked.
* **Reporting**: Formats sticky Markdown triage tables (`comment.md`) and SARIF 2.1.0 (`--output-sarif`) for GitHub Code Scanning.
* **Threat-Model Control**: `--threat-model auto|owasp|maestro` defaults to `auto`; route selection and any MAESTRO layer/cross-layer evidence are reported without changing OWASP finding identifiers.

---

## 4. Targeted Threat Model

SecAgent evaluates 8 categories from the OWASP Top 10 for Agentic AI Applications (7 trace-verifiable in YAML + static `ASI04` tool-description scan):
* **ASI01: Agent Goal Hijack**: Prompts overriding system persona (`POL-ASI01-001`) and indirect prompt injection flows (`POL-ASI01-002`).
* **ASI02: Tool Misuse**: SQL injection payloads in tool arguments (`POL-ASI02-001`).
* **ASI03: Identity & Privilege Abuse**: Predecessor approval enforcement (`POL-ASI03-001`) and context boundaries (`POL-ASI03-002`).
* **ASI04: Agentic Supply Chain Vulnerabilities**: Embedded prompt directives in tool descriptions and metadata (`POL-ASI04-001`).
* **ASI05: Unexpected Code Execution**: Command injection and shell metacharacters in tool parameters (`POL-ASI05-001`).
* **ASI06: Scope Abuse**: Over-fetching sensitive attributes (`POL-ASI06-001`).
* **ASI08: Cascading Failures**: Runaway execution loops and retry depth (`POL-ASI08-001`).
* **ASI10: Rogue Agent Egress Exfiltration**: Data transmission to untrusted endpoints (`POL-ASI10-001`).

### 4.1 Complementary CSA MAESTRO Model

MAESTRO supplies architectural context for MAS threats and does not replace the OWASP categories above. The native adapter uses the following official layers:

| Layer | SecAgent interpretation |
| :--- | :--- |
| **L1: Foundation Models** | LLMs and model APIs |
| **L2: Data Operations** | Databases, vector stores, RAG, memory, and context |
| **L3: Agent Frameworks** | Orchestration, planning, graph execution, and tool frameworks |
| **L4: Deployment & Infrastructure** | Runtime environments, containers, and network |
| **L5: Evaluation & Observability** | Telemetry, tracing, and audit logs |
| **L6: Security & Compliance** | IAM, permission checks, guardrails, HITL gates, and YAML policy enforcement |
| **L7: Agent Ecosystem** | Inter-agent protocols, external tools/APIs, and human-agent interfaces |

`maestro_layer` is an optional trace attribute. YAML policies may opt into layer-aware or cross-layer conditions, but OWASP-only traces and policies stay backwards compatible. A generated-scenario JSON Schema and policy metadata reserve nullable `external_refs` and/or `atlas_id` fields for a future mapping.

---

## 5. Work Breakdown Structure

| Engineer | Focus | Input Contract | Output Contract |
| :--- | :--- | :--- | :--- |
| **Student 1** | Agent Introspection, Topology & Routing | Agent Entrypoint (`--agent`) | Introspector, topology profile, `topology.py`, and `harness/threat_router.py` |
| **Student 2** | Scenario Generator & MAESTRO Adapter | Target Agent Tool Signatures + topology profile | OWASP generator, `src/secagent/maestro/`, `metaprompt.py`, and cached test synthesis |
| **Student 3** | Telemetry Pipeline | Agent Runtime Hooks | `src/secagent/telemetry/` span exporter & PII scrubber |
| **Student 4** | Invariant Verifier | `schemas/trace_event.schema.json` | `src/secagent/engine/` evaluator |
| **Student 5** | GitHub Action & CLI | Engine Result Models | `action.yml`, `src/secagent/cli.py`, `app.py` |

---

## 6. Evaluation Criteria

* **Privilege Violation Detection**: Flags unapproved `pay` and `admin` tool calls when predecessor HITL gate spans are absent in the trace.
* **Parameter Injection Detection**: Flags inputs matching known SQL and command injection patterns in user-controlled arguments.
* **Execution Overhead**: Complete CI evaluation runs in under 10 seconds.
* **Deterministic Precision**: Validated against compliant reference fixtures to ensure standard tool invocations pass without spurious policy triggers.

---

## 7. Alternatives Considered & Trade-offs

* **LLM-as-a-Judge vs. Deterministic Trace Rules**: LLM judges catch fuzzy semantic failures but introduce API cost, multi-second latency, and flaky CI verdicts. SecAgent chose deterministic rule evaluation on traces for sub-10ms, zero-cost, reproducible PR gates, accepting that regex/structural rules require explicit policy updates for novel phrasings.
* **Production Runtime Proxy vs. Pre-Merge CI Gate**: Inline runtime proxies block live traffic but add production latency and risk false-positive outages. SecAgent targets pre-merge CI/CD with dry-run sandboxing and baseline diffing, trading runtime interception for zero production overhead.
* **Native Adapter vs. CSA Stack Fork**: A native adapter keeps installation, testing, and CI deployment inside the existing Python process while retaining the MAESTRO taxonomy and prompt provenance. It requires disciplined source attribution and compatibility tests rather than inheriting an external runtime.

---

## 8. Future Work / v2

MITRE ATLAS TTP mapping is explicitly deferred from v1. The optional nullable `external_refs: list[str] = []` and `atlas_id: null` hooks let future policy and generated-payload contracts attach ATLAS references without changing v1 routing, policies, or verdict semantics.

Before shipping the native adapter, add an attribution entry in `CREDITS.md` or the README and source comments that reference <https://github.com/CloudSecurityAlliance/MAESTRO>.
