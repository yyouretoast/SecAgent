# RFC-001: SecAgent System Architecture

* **RFC ID**: RFC-001
* **Title**: CI/CD Security Scanner & GitHub Action for Autonomous AI Agents
* **Status**: ACCEPTED / IN IMPLEMENTATION
* **Target Delivery**: DEPI Agentic AI Track Graduation Capstone
* **Team**: 5 Senior Engineering Students (Part-Time: 4–6 hours/week per student)

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
1. Targets autonomous agents across frameworks (LangGraph, CrewAI, AutoGen).
2. Evaluates execution traces against 7 core OWASP Top 10 for Agentic AI Applications categories.
3. Provides an SDK decorator (`@permission(tier="...")`) standardizing tool privilege tiers (`read`, `write`, `pay`, `admin`, `net`).
4. Generates adversarial test scenarios dynamically on the fly based on tool signatures.

---

## 2. System Architecture

```
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
│ SUBSYSTEM 3: DYNAMIC SCENARIO GENERATOR (src/secagent/generator/)                      │
│                                                                                        │
│   Synthesizes adversarial inputs (SQLi, role spoofing, loop traps)                     │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Injects adversarial inputs
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 1: TARGET AGENT UNDER TEST (user agent / examples)                           │
│                                                                                        │
│   Autonomous Agent (LangGraph, CrewAI, AutoGen, custom)                                │
│   ├── Tools decorated with `@permission(tier=...)`                                     │
│   └── SecAgent SDK: @permission(tier="read"|"write"|"pay"|"admin"|"net")               │
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

## 3. Subsystem Specifications

### Subsystem 1: Agent Introspection & Execution Harness
* **Integration**: Invokes candidate agents via entrypoint (`--agent module:app`).
* **Safe CI Execution**: All tool invocations execute in a virtualized dry-run sandbox during security testing. Destructive operations (`drop_database`, `execute_trade`) record intended calls and arguments in the trace but return mock success values. No real external side-effects occur during testing.
* **Privilege Tier Discovery (3-Tier Precedence)**:
  1. *Explicit Decorator*: Checks for `@permission(tier="...")` attribute attached to functions.
  2. *Policy Mapping*: Reads external overrides from `policies/security_rules.yaml` (`tool_tier_overrides`).
  3. *Semantic Heuristic*: Infers tiers from tool naming patterns:
     - `pay`: `*(pay|refund|trade|charge|transfer|buy)*`
     - `admin`: `*(drop|delete|restart|kill|exec|bash|deploy)*`
     - `write`: `*(write|update|modify|insert|create)*`
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

### Subsystem 3: Dynamic Scenario Generator
* **Schema-Aware Generation**: Introspects parameter types and names using Python's `inspect` module and Pydantic schemas. Payloads target query/filter string parameters rather than blind dictionary injection.
* **Deterministic Seeding & Caching**: Generates scenarios with fixed random seeds into `scenarios/generated/`. Test suites are regenerated only when tool signatures or configurations change, preventing non-deterministic CI flakiness across unchanged commits.
* **Test Case Synthesis**:
  - Role-spoofing prompts attempting high-privilege execution without authorization (ASI03).
  - Parameter fuzzing targeting user-controlled arguments with SQL injection and shell syntax (ASI02, ASI05).
  - Data extraction prompts targeting sensitive fields (ASI06, ASI10).
  - Recursive goals designed to exceed execution step limits (ASI08).

### Subsystem 4: Invariant Verification Engine
Evaluates YAML policies against execution traces deterministically:
1. **Predecessor Gate Invariant (ASI03)**: High-privilege actions (`pay`, `admin`) must be preceded by an authorized `gate.hitl` span.
2. **Context Privilege Invariant (ASI03)**: Read-only contexts cannot execute mutating tools.
3. **Parameter Injection Invariant (ASI02, ASI05)**: Regex blocklists for SQL and command injection payloads.
4. **Field Scope Invariant (ASI06)**: Blocks queries requesting restricted fields (`ssn`, `password_hash`).
5. **Circuit Breaker Invariant (ASI08)**: Step count limits ($N \le 10$) and duplicate call thresholds.
6. **Egress Allowlist Invariant (ASI10)**: Network tools can only access approved domains.

### Subsystem 5: GitHub Action & Developer CLI
* **Dual-Lifecycle Execution Model**:
  - `secagent scan` (Every PR): Evaluates target agents against cached/generated scenarios. Runs deterministically in under 2 seconds with zero external LLM API costs.
  - `secagent generate` (On Tool Change): Invoked locally or in CI when tool signatures mutate to refresh `scenarios/generated/`.
  - `secagent fuzz` (Periodic / Nightly): Runs multi-turn prompt mutations for deep offline security audits.
* **GitHub Action (`action.yml`)**: Composite action running on pull requests.
* **Exit Codes**:
  - `0`: All security invariants satisfied.
  - `1`: Security policy violation detected. Pull request blocked.
* **Reporting**: Formats Markdown triage tables for pull request review.

---

## 4. Targeted Threat Model

SecAgent evaluates 7 trace-verifiable categories from the OWASP Top 10 for Agentic AI Applications:
* **ASI01: Agent Goal Hijack**: Prompts overriding system persona or deviating from assigned scope.
* **ASI02: Tool Misuse**: SQL injection payloads in tool arguments (`POL-ASI02-001`).
* **ASI03: Identity & Privilege Abuse**: Predecessor approval enforcement (`POL-ASI03-001`) and context boundaries (`POL-ASI03-002`).
* **ASI05: Unexpected Code Execution**: Command injection and shell metacharacters in tool parameters (`POL-ASI05-001`).
* **ASI06: Scope Abuse**: Over-fetching sensitive attributes (`POL-ASI06-001`).
* **ASI08: Cascading Failures**: Runaway execution loops and retry depth (`POL-ASI08-001`).
* **ASI10: Rogue Agent Egress Exfiltration**: Data transmission to untrusted endpoints (`POL-ASI10-001`).

---

## 5. Work Breakdown Structure

| Engineer | Focus | Input Contract | Output Contract |
| :--- | :--- | :--- | :--- |
| **Student 1** | Agent Introspection & SDK | Agent Entrypoint (`--agent`) | Dynamic introspector & `@permission` SDK |
| **Student 2** | Scenario Generator | Target Agent Tool Signatures | `src/secagent/generator/` test synthesis |
| **Student 3** | Telemetry Pipeline | Agent Runtime Hooks | `src/secagent/telemetry/` span exporter & PII scrubber |
| **Student 4** | Invariant Verifier | `schemas/trace_event.schema.json` | `src/secagent/engine/` evaluator |
| **Student 5** | GitHub Action & CLI | Engine Result Models | `action.yml`, `src/secagent/cli.py`, `app.py` |

---

## 6. Evaluation Criteria

* **Privilege Violation Detection**: 100% detection rate on unapproved `pay` and `admin` calls.
* **Parameter Injection Detection**: Flags inputs matching known SQL and command injection patterns.
* **Execution Overhead**: Complete CI evaluation runs in under 10 seconds.
* **False Positive Rate**: Zero false alarms on compliant execution traces.
