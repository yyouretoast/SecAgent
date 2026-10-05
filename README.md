# SecAgentTwin

> **Execution-Grounded Differential Testing & Security Validation for Autonomous AI Agents in CI/CD**

[![CI](https://github.com/yyouretoast/SecAgentTwin/actions/workflows/secagent-ci.yml/badge.svg)](https://github.com/yyouretoast/SecAgentTwin/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/downloads/)

SecAgentTwin is an automated DevSecOps testing framework for autonomous AI agents. Rather than grading non-deterministic text outputs using LLM-as-a-judge (which exhibits an ~89% error rate when diagnosing trace failures), SecAgentTwin performs **trace-level differential sequence alignment** against immutable golden baselines, enforces **OWASP Top 10 for Agentic AI Applications (2025)** security invariants at tool boundaries, and leverages **Chronicle cut-point replay** ([arXiv:2609.20625](https://arxiv.org/abs/2609.20625)) for zero-token, sub-second continuous regression testing in pull request workflows.

---

## Architecture Overview

![SecAgentTwin Architecture](docs/secagent_twin_c4_architecture.png)

The system decomposes into 5 decoupled subsystems connected by frozen JSON/YAML contracts:
1. **Target SUT (`src/secagent_twin/agent/`)**: Reference LangGraph customer operations agent with Human-in-the-Loop (`approval_gate`) and `@permission` tiers.
2. **Telemetry & PII (`src/secagent_twin/telemetry/`)**: OpenTelemetry GenAI span capture with deterministic in-line regex PII sanitization.
3. **Chronicle Replay (`src/secagent_twin/replay/`)**: Intercepts model calls to serve recorded envelopes via SHA-256 prompt hashing (0 live tokens).
4. **Diff & Policy Engine (`src/secagent_twin/engine/`)**: Evaluates declarative YAML policies (Tier 1) and aligns traces via Mazurkiewicz canonical read sorting (Tier 2) to pinpoint earliest divergence index $k^*$.
5. **CI/CD Gate & UI (`src/secagent_twin/cli.py`, `app.py`)**: GitHub Actions PR blocker (Exit 0/1/2) and Streamlit dual-tree trace inspector.

---

## Quickstart

### 1. Installation
```bash
git clone https://github.com/yyouretoast/SecAgentTwin.git
cd SecAgentTwin
python -m pip install -e ".[dev]"
```

### 2. Record a Golden Baseline (Offline)
Execute a known-good agent version across benchmark scenarios to commit reference traces:
```bash
secagent record --scenario scenarios/SCN-07.yaml --output baselines/golden/
```

### 3. Run Differential Security Audit (Local or CI)
Audit a candidate agent modification against committed baselines:
```bash
secagent test \
  --baseline baselines/golden/ \
  --scenarios scenarios/ \
  --policies policies/security_rules.yaml
```

### 4. Interactive Local Debugging (Streamlit Dashboard)
Inspect side-by-side execution trees and examine divergent step $k^*$:
```bash
secagent serve --baseline baselines/golden/SCN-07.json --candidate traces/candidate_SCN-07.json
```

---

## Project Structure

```
secagent-twin/
├── README.md
├── pyproject.toml
├── .github/
│   └── workflows/
│       └── secagent-ci.yml               # Automated PR blocking workflow
├── docs/
│   ├── RFC-001-architecture.md           # Master technical specification
│   ├── CONTRIBUTING.md                   # Development & branch conventions
│   ├── secagent_twin_c4_architecture.png # Publication-grade C4 diagram (300 DPI)
│   ├── secagent_twin_c4_architecture.svg # Vector architecture companion
│   └── secagent_twin_c4_architecture.tex # LaTeX TikZ diagram source
├── schemas/
│   └── trace_event.schema.json           # Formal OpenTelemetry trace contract
├── policies/
│   └── security_rules.yaml               # Declarative OWASP invariant rules
├── scenarios/
│   └── TEMPLATE.yaml                     # Attack scenario manifest template
└── src/
    └── secagent_twin/                    # Core Python package implementation
```

---

## Documentation

* [RFC-001: System Architecture & Technical Specification](docs/RFC-001-architecture.md)
* [Team Development & Contribution Guide](docs/CONTRIBUTING.md)
* [Trace Event JSON Schema](schemas/trace_event.schema.json)
* [Security Rules Specification](policies/security_rules.yaml)

---

## License

Apache License 2.0. See LICENSE for details.
