# SecAgent

> **Automated OWASP Security Scanner & GitHub Action for Autonomous AI Agents**

[![CI](https://github.com/yyouretoast/SecAgent/actions/workflows/secagent-ci.yml/badge.svg)](https://github.com/yyouretoast/SecAgent/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/downloads/)

SecAgent is an automated security scanner and GitHub Action designed to test autonomous AI agents (LangGraph, CrewAI, AutoGen) against the **OWASP Top 10 for Agentic AI Applications**. 

SecAgent integrates directly into CI/CD pipelines to block pull requests on unauthorized privilege escalations, missing predecessor human-in-the-loop (HITL) gates, parameter injections, context scope violations, and runaway execution loops.

---

## Architecture Overview

```mermaid
flowchart TD
    classDef pr fill:#eff6ff,stroke:#2563eb,stroke-width:1.5px,color:#1e3a8a,font-weight:bold;
    classDef cicd fill:#f1f5f9,stroke:#475569,stroke-width:1.5px,color:#0f172a;
    classDef fuzzer fill:#faf5ff,stroke:#9333ea,stroke-width:1.5px,color:#581c87;
    classDef sut fill:#f8fafc,stroke:#64748b,stroke-width:1.5px,color:#0f172a;
    classDef otel fill:#f0fdf4,stroke:#16a34a,stroke-width:1.5px,color:#14532d;
    classDef rules fill:#fffbeb,stroke:#d97706,stroke-width:1.5px,color:#78350f;
    classDef pass fill:#ecfdf5,stroke:#059669,stroke-width:1.5px,color:#065f46;
    classDef fail fill:#fff1f2,stroke:#e11d48,stroke-width:1.5px,color:#9f1239;

    PR["⚡ Developer Pull Request<br/><sub>(Prompt patch, tool change, model upgrade)</sub>"]:::pr

    subgraph CI ["Subsystem 5: Turnkey CI/CD Security Gate (action.yml)"]
        Action["GitHub Action Runner<br/><code>secagent scan / fuzz</code>"]
        PassGate["Exit Code 0: PASS<br/><sub>Allow PR Merge</sub>"]:::pass
        FailGate["Exit Code 1: FAIL<br/><sub>Block PR & Post Security Triage</sub>"]:::fail
    end
    class CI cicd;

    subgraph Adversary ["Subsystem 3: Dynamic Adversarial Fuzzer"]
        Fuzzer["Adversarial Prompt Mutator<br/><code>secagent fuzz</code><br/><sub>SQLi, jailbreaks, parameter injection</sub>"]
    end
    class Adversary fuzzer;

    subgraph SUT ["Subsystem 1: Target Autonomous Agent Under Test"]
        DevOps["LangGraph / CrewAI / AutoGen Agent<br/><sub>Tools decorated with <code>@permission</code></sub>"]
    end
    class SUT sut;

    subgraph Telemetry ["Subsystem 2: Telemetry & PII Sanitizer (src/secagent/telemetry/)"]
        OTel["OpenTelemetry Span Capture<br/><code>agent.run | tool.call | gate.hitl</code>"]
        Scrubber["In-Line PII & Secret Redactor<br/><code>Regex SSN / Auth token scrubber</code>"]
        TraceJSON["Standard Execution Trace JSON<br/><code>schemas/trace_event.schema.json</code>"]
    end
    class Telemetry otel;

    subgraph Security ["Subsystem 4: Invariant Verification Engine"]
        Verifier["Policy Verifier (policies/security_rules.yaml)<br/><sub>Predecessor gates, loop breaker, regex checks</sub>"]
    end
    class Security rules;

    PR -->|Triggers Workflow| Action
    Action -->|Dispatches Test Scenarios| Fuzzer
    Fuzzer -->|Injects Mutated Prompts| SUT
    SUT -->|Streams Spans| OTel
    OTel -->|Raw Spans| Scrubber
    Scrubber -->|Redacted Spans| TraceJSON
    TraceJSON -->|Evaluates Invariants| Verifier
    Verifier -->|Exit Code 0 / No Breaches| PassGate
    Verifier -->|Exit Code 1 / OWASP Invariant Breached| FailGate
```

### CI/CD Security Audit Execution Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / PR
    participant CI as GitHub Action (action.yml)
    participant Fuzz as Dynamic Fuzzer (Subsystem 3)
    participant Agent as Target Agent (Subsystem 1)
    participant Telem as Telemetry & PII Redactor (Subsystem 2)
    participant Engine as OWASP Policy Verifier (Subsystem 4)

    Dev->>CI: Open Pull Request / Push Commit
    CI->>Fuzz: Launch secagent fuzz --iterations N
    loop Adversarial Fuzzing & Mutation
        Fuzz->>Agent: Dispatch Mutated Adversarial Prompt (SQLi, Jailbreak)
        activate Agent
        Agent->>Agent: Evaluate Policy & Invoke Tools (@permission)
        Agent->>Telem: Stream OTel Spans (agent.run, tool.call)
        deactivate Agent
        activate Telem
        Telem->>Telem: Scrub PII / Tokens & Serialize to trace.json
        deactivate Telem
    end
    CI->>Engine: Run secagent scan trace.json --rules security_rules.yaml
    activate Engine
    Engine->>Engine: Check HITL Predecessors, Scope, & Recursion Limits
    Engine-->>CI: Return Evaluation Results (Exit Code 0 / 1)
    deactivate Engine
    alt Invariant Breached (OWASP Top 10 Violation)
        CI-->>Dev: ❌ Block PR Merge & Post Security Triage Report
    else All Security Invariants Satisfied
        CI-->>Dev: ✅ Approve CI & Allow Pull Request Merge
    end
```

---

## Key Features

1. **Universal GitHub Action (`action.yml`)**: Drop-in action for GitHub workflows. Blocks PR merges automatically when an agent breaches declarative security invariants.
2. **Multi-Domain Agent Support**: Compatible with any autonomous agent domain (DevOps infrastructure, Quantitative Finance, Customer Operations, Data Science).
3. **Universal Privilege SDK (`@secagent.permission`)**: Standardized tool permission tiers (`read`, `write`, `pay`, `admin`, `net`).
4. **Deterministic Invariant Verification**: Verifies OWASP rules (ASI01 Goal Hijacking, ASI02 Tool Misuse, ASI03 Privilege Abuse, ASI06 Scope Contamination, ASI08 Cascading Loops) directly on execution traces without subjective LLM-as-a-judge grading.
5. **Dynamic Adversarial Fuzzing (`secagent fuzz`)**: Automated prompt mutation engine to uncover unhandled edge-cases and jailbreak regressions.
6. **Local Security Dashboard (`secagent serve`)**: Interactive visualization of security audits and trace lifecycles.

---

## Quickstart

### 1. Installation
```bash
git clone https://github.com/yyouretoast/SecAgent.git
cd SecAgent
python -m pip install -e ".[dev]"
```

### 2. Protect Agent Tools
Apply `@permission` to your agent's tools:
```python
from secagent.sdk import permission


@permission(tier="admin")
def restart_server(server_id: str) -> dict:
    """Privileged admin command."""
    return {"server": server_id, "status": "restarted"}


@permission(tier="pay")
def execute_trade(symbol: str, quantity: int) -> dict:
    """Financial trade requiring predecessor approval."""
    return {"order": "filled", "symbol": symbol, "quantity": quantity}
```

### 3. Run Dynamic Security Scan
Audit an agent against dynamically synthesized adversarial attacks:
```bash
secagent scan --agent examples.finance_agent.agent:run_finance_agent --policies policies/security_rules.yaml
```

### 4. Dynamic Scenario Synthesis & Fuzzing
Generate adversarial mutations on the fly without writing static YAML files:
```bash
# Synthesize dynamic scenarios tailored to agent tool definitions
secagent generate --agent examples.devops_agent.agent:run_devops_agent --per-tool 3

# Fuzz agent with dynamic adversarial mutations
secagent fuzz --agent examples.support_agent.agent:run_support_agent --iterations 10
```

### 5. GitHub Action Integration
Add `SecAgent` to `.github/workflows/security.yml`:
```yaml
name: Agent Security Audit
on: [pull_request]

jobs:
  secagent-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Run SecAgent Dynamic Security Gate
        uses: ./ # Or yyouretoast/SecAgent@main
        with:
          agent_entrypoint: "my_agent.graph:app"
          policies: "policies/security_rules.yaml"
          output_report: "report.json"
          output_markdown: "comment.md"
```

---

## Project Structure

```
secagent/
├── action.yml                         # Universal GitHub Action definition
├── pyproject.toml                     # Project packaging & CLI entrypoints
├── .github/
│   └── workflows/
│       └── secagent-ci.yml            # CI workflow running scanner & pytest
├── docs/
│   ├── RFC-001-architecture.md        # Technical architecture specification
│   ├── CONTRIBUTING.md                # Development & branch conventions
│   └── PLAYBOOK.md                    # Student role breakdown & milestones
├── examples/                          # Smoke-test fixture agents (smoke test harness)
│   ├── devops_agent/agent.py          # DevOps agent (admin tier)
│   ├── finance_agent/agent.py         # Finance agent (pay tier)
│   └── support_agent/agent.py         # Customer support agent
├── schemas/
│   └── trace_event.schema.json        # Standardized OpenTelemetry trace schema
├── policies/
│   └── security_rules.yaml            # Declarative OWASP invariant rules
├── src/
│   └── secagent/
│       ├── cli.py                     # Typer CLI (generate, scan, fuzz, serve)
│       ├── generator/                 # Dynamic adversarial scenario synthesizer
│       ├── sdk/                       # @permission decorator & tools
│       └── agent/state.py             # Agent runtime state contract
└── tests/
    └── test_contracts.py              # Pytest schema and CLI contract suite
```

---

## Documentation

* [RFC-001: Architecture & Technical Specification](docs/RFC-001-architecture.md)
* [Team Development & Contribution Guide](docs/CONTRIBUTING.md)
* [Team Kickoff & Implementation Playbook](docs/PLAYBOOK.md)
* [Trace Event JSON Schema](schemas/trace_event.schema.json)
* [Security Rules Specification](policies/security_rules.yaml)

---

## License

Apache License 2.0. See LICENSE for details.
