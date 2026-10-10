# SecAgent

CI/CD security gate and testing tool for autonomous AI agents (LangGraph, CrewAI, AutoGen). Evaluates execution traces against the OWASP Top 10 for Agentic AI Applications.

[![CI](https://github.com/yyouretoast/SecAgent/actions/workflows/secagent-ci.yml/badge.svg)](https://github.com/yyouretoast/SecAgent/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/downloads/)

---

## What SecAgent Does

When developers change system prompts, tool schemas, or underlying models, agents can introduce security regressions:
* Executing sensitive financial actions without required approval gates (ASI03).
* Passing unvalidated user input into database or shell tools (ASI02, ASI05).
* Exfiltrating internal data or over-fetching sensitive fields (ASI06, ASI10).
* Getting trapped in non-terminating execution loops (ASI08).

SecAgent runs in CI/CD pipelines, synthesizes adversarial attack scenarios tailored to the agent's tools, executes the agent, inspects its execution trace, and blocks pull requests if security boundaries are breached.

---

## Architecture

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

    PR["Developer Pull Request"]:::pr

    subgraph CI ["CI/CD Gate (action.yml)"]
        Action["GitHub Action Runner<br/><code>secagent scan / fuzz</code>"]
        PassGate["Exit 0: PASS<br/>Allow Merge"]:::pass
        FailGate["Exit 1: FAIL<br/>Block PR & Post Triage"]:::fail
    end
    class CI cicd;

    subgraph Adversary ["Adversarial Fuzzer (src/secagent/generator/)"]
        Fuzzer["Scenario Generator<br/><code>secagent generate / fuzz</code>"]
    end
    class Adversary fuzzer;

    subgraph SUT ["Target Agent Under Test"]
        DevOps["Candidate Agent<br/>Tools decorated with <code>@permission</code>"]
    end
    class SUT sut;

    subgraph Telemetry ["Telemetry & Redactor (src/secagent/telemetry/)"]
        OTel["OTel Span Capture"]
        Scrubber["PII & Secret Redactor"]
        TraceJSON["Execution Trace JSON"]
    end
    class Telemetry otel;

    subgraph Security ["Invariant Verifier (policies/security_rules.yaml)"]
        Verifier["Policy Engine<br/>Predecessor gates, regex, circuit breakers"]
    end
    class Security rules;

    PR -->|Triggers| Action
    Action -->|Dispatches Scenarios| Fuzzer
    Fuzzer -->|Injects Mutated Inputs| SUT
    SUT -->|Streams Spans| OTel
    OTel --> Scrubber --> TraceJSON
    TraceJSON -->|Evaluates| Verifier
    Verifier -->|Passed| PassGate
    Verifier -->|Violated| FailGate
```

### Execution Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / PR
    participant CI as GitHub Action (action.yml)
    participant Fuzz as Scenario Generator
    participant Agent as Target Agent
    participant Telem as Telemetry & PII Redactor
    participant Engine as Policy Verifier

    Dev->>CI: Open Pull Request / Push Commit
    CI->>Fuzz: Run secagent fuzz / scan
    loop Adversarial Testing
        Fuzz->>Agent: Dispatch adversarial prompt / parameters
        activate Agent
        Agent->>Agent: Execute tool calls (@permission)
        Agent->>Telem: Stream execution spans
        deactivate Agent
        activate Telem
        Telem->>Telem: Redact PII / tokens -> write trace.json
        deactivate Telem
    end
    CI->>Engine: Evaluate trace.json against policies
    activate Engine
    Engine->>Engine: Check predecessor gates, parameter regex, step limits
    Engine-->>CI: Verdict (Exit 0 or Exit 1)
    deactivate Engine
    alt Invariant Violated
        CI-->>Dev: Block PR & Post Security Triage
    else Invariants Passed
        CI-->>Dev: Pass CI & Allow Merge
    end
```

---

## Core Capabilities

* **GitHub Action (`action.yml`)**: Blocks pull requests automatically when an agent breaches declarative security rules.
* **Deterministic Checks**: Verifies approval gates, argument patterns, and recursion limits directly from OpenTelemetry traces. No LLM-as-a-judge.
* **Automatic Test Generation (`secagent generate`)**: Inspects agent tools and generates test cases without manually written YAML files.
* **Privilege SDK (`@secagent.permission`)**: Decorator for tools specifying execution privilege tiers (`read`, `write`, `pay`, `admin`, `net`).
* **Trace-Observable OWASP Coverage**: Covers 7 agentic vulnerability categories (ASI01, ASI02, ASI03, ASI05, ASI06, ASI08, ASI10).

---

## Quickstart

### 1. Installation

```bash
git clone https://github.com/yyouretoast/SecAgent.git
cd SecAgent
python -m pip install -e ".[dev]"
```

### 2. Protect Agent Tools

Decorate sensitive agent tools with `@permission`:

```python
from secagent.sdk import permission


@permission(tier="admin")
def restart_server(server_id: str) -> dict:
    """Restarts host infrastructure."""
    return {"server": server_id, "status": "restarted"}


@permission(tier="pay")
def execute_trade(symbol: str, quantity: int) -> dict:
    """Executes market order. Requires prior HITL approval."""
    return {"order": "filled", "symbol": symbol, "quantity": quantity}
```

### 3. Run a Security Scan

Run a scan against an agent entrypoint:

```bash
secagent scan --agent examples.finance_agent.agent:run_finance_agent --policies policies/security_rules.yaml
```

### 4. Synthesize Test Scenarios

Generate adversarial test cases by inspecting the agent's tool definitions:

```bash
secagent generate --agent examples.devops_agent.agent:run_devops_agent --per-tool 3
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
      - name: Run SecAgent Security Gate
        uses: ./
        with:
          agent_entrypoint: "my_agent.graph:app"
          policies: "policies/security_rules.yaml"
          output_report: "report.json"
          output_markdown: "comment.md"
```

---

## Repository Structure

```
secagent/
├── action.yml                         # GitHub Action composite definition
├── pyproject.toml                     # Project packaging & CLI entrypoints
├── .github/
│   ├── workflows/secagent-ci.yml      # CI workflow running scanner & pytest
│   └── pull_request_template.md       # Team PR checklist & template
├── docs/
│   ├── RFC-001-architecture.md        # Technical specification
│   ├── CONTRIBUTING.md                # Development workflow & conventions
│   └── PLAYBOOK.md                    # Work breakdown & student roles
├── examples/                          # Smoke-test fixture agents
│   ├── devops_agent/agent.py          # DevOps agent (admin tier)
│   ├── finance_agent/agent.py         # Finance agent (pay tier)
│   └── support_agent/agent.py         # Support agent (multi-tier)
├── schemas/
│   └── trace_event.schema.json        # Trace JSON schema (Draft 2020-12)
├── policies/
│   └── security_rules.yaml            # OWASP invariant policy rules
├── scenarios/
│   └── TEMPLATE.yaml                  # Scenario manifest template
├── src/
│   └── secagent/
│       ├── cli.py                     # Typer CLI (generate, scan, fuzz, serve)
│       ├── generator/                 # Dynamic scenario synthesis engine
│       ├── sdk/                       # @permission decorator & exports
│       └── agent/state.py             # LangGraph runtime state contract
└── tests/
    ├── fixtures/                      # Compliant and violating trace fixtures
    └── test_contracts.py              # Schema and CLI contract test suite
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
