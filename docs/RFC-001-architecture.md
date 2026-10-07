# RFC-001: SecAgent System Architecture & Technical Specification

* **RFC ID**: RFC-001
* **Title**: Universal CI/CD Security Scanner & GitHub Action for Autonomous AI Agents
* **Target Repository**: `https://github.com/yyouretoast/SecAgent`
* **Status**: ACCEPTED / IN IMPLEMENTATION
* **Target Delivery**: DEPI Agentic AI Track Graduation Capstone
* **Team**: 5 Senior Engineering Students (Part-Time: 4–6 hours/week per student)

---

## 1. Problem Statement & Motivation

### 1.1 The Security Vulnerability Problem in Autonomous AI Agents
Autonomous AI agents differ fundamentally from traditional software: they are non-deterministic, dynamic, and stateful. When developers update an agent (refining system prompts, upgrading models, or altering tool schemas), the agent frequently introduces **critical security regressions**:
* An agent may output polite, grammatically fluent text while internally bypassing a mandatory human authorization check before executing a high-risk operation.
* An agent may invoke high-privilege operations (e.g., executing a financial trade, deleting server infrastructure, or mutating an admin database record) when the context only warranted a read-only inquiry.
* An agent may fall into an infinite retry loop or execute unvalidated SQL/shell metacharacters inside tool arguments.

### 1.2 Inadequacy of Existing Tooling
Existing testing paradigms fail to address this problem:
1. **Output-Based LLM-as-a-Judge**: Evaluates only the final text string returned to the user. It cannot observe intermediate tool calls, skipped approval gates, or internal privilege violations.
2. **Traditional SAST/DAST Linters**: Static code linters analyze static ASTs and cannot anticipate dynamic ReAct reasoning trajectories or prompt-driven privilege escalation.
3. **Observability Dashboards**: Log passive telemetry post-mortem without providing automated, blocking CI/CD pull request gates that halt builds before deployment.

### 1.3 SecAgent Objective
SecAgent delivers a turn-key, universal **GitHub Action and CLI security scanner** that:
1. Evaluates LangGraph and autonomous agents across multiple domains (DevOps, Finance, Support, Data).
2. Enforces hard **OWASP Top 10 for Agentic AI Applications** security invariants directly on PRs via a native `action.yml` step.
3. Features an open SDK (`@permission(tier="...")`) standardizing privilege tiers (`read`, `write`, `pay`, `admin`, `net`).
4. Includes an active adversarial scenario fuzzer (`secagent fuzz`) that dynamically mutates attack vectors to uncover zero-day prompt jailbreaks and privilege leaks.

### 1.4 Scope & Generalizability
SecAgent is designed to be agent- and domain-agnostic. The policy engine is declarative and YAML-driven: rules reference generic span attributes (`permission_tier`, `span_type`, `approval_granted`, input parameters) rather than domain-specific internals. Integrating any agent into CI requires only decorating tools with `@permission` and running `secagent scan` in GitHub Actions.

---

### 2. System Architecture & Subsystem Decomposition

SecAgent is structured into **5 decoupled subsystems** connected by formal JSON/YAML schema contracts:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECAGENT SYSTEM ARCHITECTURE                         │
└────────────────────────────────────────────────────────────────────────────────────────┘

  Developer Pull Request (Prompt patch, tool change, model upgrade)
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 5: TURNKEY CI/CD GATE & CLI RUNNER (action.yml / src/secagent/cli.py)        │
│                                                                                        │
│   GitHub Action Runner executes `secagent scan` / `secagent fuzz`                      │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Dispatches test scenario & fuzz parameters
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 3: DYNAMIC SCENARIO FUZZER (src/secagent/fuzzer/)                            │
│                                                                                        │
│   Dynamic Adversarial Mutator                                                          │
│   ├── Generates adversarial prompts & SQLi/jailbreak payloads                          │
│   └── Dispatches multi-turn test vectors to Target Agents                              │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Injects adversarial prompts
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 1: TARGET AUTONOMOUS AGENT UNDER TEST (user agent / examples)                │
│                                                                                        │
│   Autonomous Agent Frameworks (LangGraph, CrewAI, AutoGen, custom)                     │
│   ├── User Agent Tools decorated with `@permission`                                    │
│   ├── Optional Reference Fixtures (DevOps, Finance, Support in examples/)              │
│   └── SecAgent SDK: @permission(tier="read"|"write"|"pay"|"admin"|"net")               │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ OpenTelemetry GenAI Spans
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 2: TELEMETRY & PII SCRUBBING PIPELINE (src/secagent/telemetry/)              │
│                                                                                        │
│   Span Instrumentation Layer                                                           │
│   ├── agent.run             (Overall execution session, task context, caller role)     │
│   ├── model.inference       (Prompts, completions, model configs, token counts)        │
│   ├── tool.call             (Tool name, input parameters, outputs, permission tier)    │
│   └── gate.hitl             (Approval request, decision boolean, approver context)     │
│   └── In-line PII Scrubber ──► Execution Trace JSON (schemas/trace_event.schema.json)  │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Standardized Trace JSON
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SUBSYSTEM 4: INVARIANT SECURITY ENGINE (src/secagent/engine/)                          │
│                                                                                        │
│   Deterministic OWASP Policy Verifier (policies/security_rules.yaml)                   │
│   ├── Enforces mandatory HITL predecessor gates (pay / admin tiers)                    │
│   ├── Checks permission tier context boundaries & scope allowlists                     │
│   └── Parameter injection regex blocklists & recursion loop thresholds                 │
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

## 3. Subsystem Detailed Specifications

### Subsystem 1: Universal Agent Introspection Harness & SDK
* **Target Integration**: Attaches to any user agent via entrypoint (`--agent module:app`, LangGraph `StateGraph`, CrewAI, or HTTP endpoint).
* **Zero Mock Overhead**: Users test their real agents; minimal reference agents in `examples/` exist solely as automated smoke-test verification fixtures.
* **Universal Permission SDK**:
  ```python
  from secagent.sdk import permission


  @permission(tier="admin")
  def restart_server(server_id: str) -> dict: ...


  @permission(tier="pay")
  def execute_trade(symbol: str, quantity: int) -> dict: ...
  ```
* Standardized privilege tiers: `read`, `write`, `pay`, `admin`, `net`.

### Subsystem 2: Telemetry & Instrumentation Pipeline
* **Telemetry Standard**: OpenTelemetry GenAI Semantic Conventions (`trace_event.schema.json`).
* **PII Scrubbing Pass**: In-line regex scrubber sanitizing SSNs, credit cards, and API secrets.
* **Trace Exporter**: Writes execution trace JSON logs with structured span arrays.

### Subsystem 3: Dynamic Scenario Synthesizer & Adversarial Fuzzer
* **Zero Static YAML Reliance**: Synthesizes adversarial attack vectors dynamically (`secagent generate` / `secagent fuzz`) by introspecting agent tool definitions and permission tiers.
* Automatically synthesizes:
  - Role-spoofing prompts attempting high-privilege execution without authorization (ASI03).
  - Parameter-level fuzzing with SQL injection (`' OR 1=1`) and command injection (`; id`) payloads (ASI02).
  - Data exfiltration prompts targeting PII / secrets (ASI06).
  - Conflicting constraints triggering runaway recursion loops (ASI08).

### Subsystem 4: Invariant Security Policy Engine
Evaluates machine-readable YAML policies against execution traces deterministically:
1. **Predecessor Gate Invariant (ASI03)**: High-privilege actions (`pay`, `admin`) must be preceded by an authorized `gate.hitl` span.
2. **Context Privilege Invariant (ASI03)**: Read-only contexts are strictly forbidden from executing mutating tools (`write`, `pay`, `admin`).
3. **Need-to-Know Scope Invariant (ASI06 sub-vector)**: Blocks over-fetching sensitive fields (`ssn`, `password_hash`) into agent context.
4. **Parameter Injection Invariant (ASI02)**: Regular expression blocklists against SQL injection and command injection payloads.
5. **Circuit Breaker Invariant (ASI08)**: Termination limits on total step counts ($N \le 10$) and consecutive duplicate tool calls.

### Subsystem 5: GitHub Action & CI/CD Security Gate
* **GitHub Action (`action.yml`)**: Drop-in composite action executing on pull requests.
* **Exit Codes**:
  - `0`: All security invariants satisfied. PR merge allowed.
  - `1`: Security policy violation detected. PR blocked.
* **PR Reporting**: Automatically generates markdown audit tables for PR review.
* **Streamlit UI**: Local web application (`secagent serve`) for trace investigation.

---

## 4. Targeted Threat Model: OWASP Top 10 for Agentic AI Applications

SecAgent targets **7 critical trace-observable OWASP Agentic categories**:
* **ASI01: Agent Goal Hijack**: Detected when adversarial inputs override system persona or cause the agent to deviate into unauthorized tool dispatches.
* **ASI02: Tool Misuse & Exploitation**: Detected via regex blocklists inspecting tool arguments for SQL injection payloads (`POL-ASI02-001`).
* **ASI03: Identity & Privilege Abuse**: Enforced via predecessor HITL gates (`POL-ASI03-001`) and context privilege boundaries (`POL-ASI03-002`).
* **ASI05: Unexpected Code Execution (RCE)**: Enforced via shell metacharacter and arbitrary code execution parameter blocklists (`POL-ASI05-001`).
* **ASI06: Context Poisoning / Scope Abuse**: Enforced via need-to-know parameter scope allowlists (`POL-ASI06-001`).
* **ASI08: Cascading Failures**: Enforced via step thresholds and idempotency circuit breakers (`POL-ASI08-001`).
* **ASI10: Rogue Agent Egress Exfiltration**: Enforced via unauthorized network egress destination allowlists (`POL-ASI10-001`).

---

## 5. Team Division of Labor & WBS

| Engineer | Subsystem Focus | Input Contract | Output Contract |
| :--- | :--- | :--- | :--- |
| **Student 1** | Universal Agent Harness & SDK | Agent Entrypoint (`--agent`) | Dynamic introspector & `@permission` SDK |
| **Student 2** | Dynamic Scenario Synthesizer | Target Agent Tool Signatures | `src/secagent/generator/` synthesized test vectors |
| **Student 3** | Telemetry & OTel Pipeline | Target Agent Runtime Hooks | `src/secagent/telemetry/` span exporter & PII scrubber |
| **Student 4** | Invariant Verifier & Fuzzer | `schemas/trace_event.schema.json` | `src/secagent/engine/` & `src/secagent/fuzzer/` |
| **Student 5** | GitHub Action & CLI Dashboard | Engine Result Models | `action.yml`, `src/secagent/cli.py`, `app.py` |

---

## 6. Capstone Empirical Evaluation Plan

SecAgent will be evaluated across a benchmark suite and dynamic fuzz runs:
* **Unauthorized Tool Call Detection Recall**: $100\%$ on structural privilege escalations and missing HITL gates.
* **Parameter Injection Recall**: $\ge 90\%$ on adversarial payloads containing SQL and command injections.
* **CI Execution Latency**: $< 10$ seconds per PR audit run.
* **Zero False Positives on Compliant Agents**: Benign agent modifications respecting invariant boundaries achieve clean passes (Exit Code 0).

