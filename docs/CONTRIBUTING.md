# SecAgentTwin — Team Contribution & Development Guide

**Target Delivery**: 12 Weeks (DEPI Agentic AI Track Graduation Capstone)  
**Team**: 5 Senior Engineering Students (Part-Time: 10–15 hours/week per student)

---

## 1. Golden Rules of Development

1. **Contract Freeze**:
   - `schemas/trace_event.schema.json` and `policies/security_rules.yaml` are **frozen**.
   - No team member may alter field names or types in these files without explicit unanimous team agreement.
2. **Subsystem Isolation**:
   - Work strictly within your assigned module under `src/secagent_twin/`.
   - Never import implementation details across boundaries — communicate only via typed models conforming to `trace_event.schema.json`.
3. **Zero-Token CI**:
   - All regression tests executed in GitHub Actions must run against `Chronicle` replay baselines (`baselines/golden/`). Never commit tests that make live, unmocked LLM API calls.
4. **Code Quality**:
   - Code must pass `ruff check .` and `ruff format --check .` before opening a pull request.
   - Type hints (`typing`, `pydantic`) are required on all public functions.

---

## 2. Team Module Ownership & WBS

| Student | Assigned Role | Primary Directory | Deliverable Artifact |
| :--- | :--- | :--- | :--- |
| **Student 1** | Target Agent Lead | `src/secagent_twin/agent/` | `agent.py`: Runnable LangGraph app with 4 mock tools & `@permission` decorators |
| **Student 2** | Security Benchmark Lead | `scenarios/` | 15 scenario YAML files (`SCN-01.yaml` to `SCN-15.yaml`) conforming to `TEMPLATE.yaml` |
| **Student 3** | Telemetry & Replay Lead | `src/secagent_twin/telemetry/`, `replay/` | `telemetry.py` (OTel exporter + PII scrubber) & `replay.py` (`ReplayChatModel` proxy) |
| **Student 4** | Diff Engine Lead | `src/secagent_twin/engine/` | `engine.py`: Tier 1 Policy Verifier + Tier 2 Canonical Aligner ($k^*$) |
| **Student 5** | CI/CD & Integration Lead | `src/secagent_twin/cli.py`, `app.py`, `.github/` | Typer CLI (`secagent test`), Streamlit UI, and GitHub Actions PR workflow |

---

## 3. Git Branch & Pull Request Workflow

### Branch Naming Conventions
```
feat/s1-target-agent-nodes
feat/s2-benchmark-scenarios
feat/s3-otel-telemetry-pipeline
feat/s4-policy-diff-engine
feat/s5-cli-and-streamlit-dashboard
fix/issue-description
```

### Pull Request Rules
1. Branch off `main` and keep pull requests focused (under 300 lines of diff where possible).
2. Ensure local tests pass:
   ```bash
   pytest tests/
   ruff check .
   ```
3. Open a PR against `main`. The automated `.github/workflows/secagent-ci.yml` will trigger and run `secagent test`.
4. Merging requires:
   - Green CI build (Exit Code 0).
   - At least 1 review sign-off from an affected subsystem owner.

---

## 4. Local Development Setup

```bash
# 1. Clone repository
git clone https://github.com/yyouretoast/SecAgentTwin.git
cd SecAgentTwin

# 2. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# 3. Install in editable mode with dev tools
pip install -e ".[dev]"

# 4. Verify installation
secagent --help
```
