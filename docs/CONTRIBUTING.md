# SecAgent — Team Contribution & Development Guide

**Target Delivery**: DEPI Agentic AI Track Graduation Capstone  
**Team**: 5 Senior Engineering Students (Part-Time: 4–6 hours/week per student)

---

## 1. Golden Rules of Development

1. **Contract Freeze**:
   - `schemas/trace_event.schema.json` and `policies/security_rules.yaml` are authoritative.
   - Maintain compatibility across agent domains (DevOps, Finance, Support).
2. **Subsystem Isolation**:
   - Work strictly within your assigned module under `src/secagent/`.
   - Never import internal implementation details across boundaries — communicate via typed models.
3. **Deterministic CI**:
   - Continuous integration audits must run deterministically via `action.yml` and `secagent scan`.
4. **Code Quality**:
   - Code must pass `ruff check .` and `pytest tests/` before opening a pull request.
   - Type hints (`typing`, `pydantic`) are required on all public functions.

---

## 2. Team Module Ownership & WBS

| Student | Assigned Role | Primary Directory | Deliverable Artifact |
| :--- | :--- | :--- | :--- |
| **Student 1** | Agent Harness & Introspection Lead | `src/secagent/harness/`, `src/secagent/sdk/` | Dynamic agent introspector + `@permission` SDK |
| **Student 2** | Dynamic Scenario Generator Lead | `src/secagent/generator/` | Automated adversarial scenario synthesizer (`secagent generate`) |
| **Student 3** | Telemetry & OTel Lead | `src/secagent/telemetry/` | OpenTelemetry span processor, PII scrubbing, trace exporter |
| **Student 4** | Invariant Verifier & Fuzz Lead | `src/secagent/engine/`, `fuzzer/` | Policy Invariant Verifier + Dynamic Scenario Fuzzer |
| **Student 5** | GitHub Action & UI Lead | `action.yml`, `src/secagent/cli.py`, `app.py`, `.github/` | Composite GitHub Action, Typer CLI, and Streamlit report UI |

---

## 3. Git Branch & Pull Request Workflow

### Branch Naming Conventions
```
feat/s1-target-agents
feat/s2-benchmark-scenarios
feat/s3-otel-telemetry-pipeline
feat/s4-policy-fuzzer-engine
feat/s5-github-action-cli-ui
fix/issue-description
```

### Pull Request Rules
1. Branch off `main` and keep pull requests focused.
2. Ensure local tests pass:
   ```bash
   pytest tests/
   ruff check .
   ```
3. Open a PR against `main`. The automated `.github/workflows/secagent-ci.yml` will trigger and run `secagent scan`.
4. Merging requires:
   - Green CI build (Exit Code 0).
   - At least 1 review sign-off.

---

## 4. Local Development Setup

```bash
# 1. Clone repository
git clone https://github.com/yyouretoast/SecAgent.git
cd SecAgent

# 2. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# 3. Install in editable mode with dev tools
pip install -e ".[dev]"

# 4. Verify installation
secagent --help
```
