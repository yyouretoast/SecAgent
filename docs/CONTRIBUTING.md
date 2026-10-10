# Contribution Guide

Guidelines for contributing to SecAgent.

---

## 1. Development Principles

1. **Contract Stability**:
   * `schemas/trace_event.schema.json` and `policies/security_rules.yaml` define system interfaces.
   * Changes to these files require team consensus.
2. **Subsystem Isolation**:
   * Keep implementation code within your assigned module under `src/secagent/`.
   * Interact across boundaries using typed data contracts.
3. **Deterministic CI**:
   * Continuous integration audits must execute deterministically without external API dependencies.
4. **Code Quality**:
   * All code must pass `ruff check .`, `ruff format --check .`, and `pytest tests/` before opening a pull request.
   * Type annotations are required on public functions.

---

## 2. Module Ownership

| Student | Role | Primary Directory | Deliverable Artifact |
| :--- | :--- | :--- | :--- |
| **Student 1** | Agent Harness & Introspection | `src/secagent/harness/`, `src/secagent/sdk/` | Dynamic introspector + `@permission` SDK |
| **Student 2** | Scenario Generator | `src/secagent/generator/` | Automated scenario synthesizer (`secagent generate`) |
| **Student 3** | Telemetry & OTel | `src/secagent/telemetry/` | Span collector, PII scrubber, trace exporter |
| **Student 4** | Policy Engine | `src/secagent/engine/` | Policy invariant evaluator |
| **Student 5** | GitHub Action & CLI | `action.yml`, `src/secagent/cli.py`, `app.py`, `.github/` | Composite action, Typer CLI, Streamlit UI |

---

## 3. Pull Request Workflow

1. Create a focused branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Verify locally:
   ```bash
   pytest tests/ -v
   ruff check .
   ruff format --check .
   ```
3. Open a pull request against `main`. Fill out the checklist in `.github/pull_request_template.md`.
4. Merging requires a passing CI workflow and review approval.

---

## 4. Local Setup

```bash
git clone https://github.com/yyouretoast/SecAgent.git
cd SecAgent

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pytest tests/ -v
```
