## Description
<!-- Provide a brief description of what this PR introduces or fixes. -->

## Subsystem Addressed
- [ ] Subsystem 1: Target Agent Introspection & Universal SDK (`src/secagent/harness/`, `src/secagent/sdk/`)
- [ ] Subsystem 2: Telemetry & In-Line PII Redactor (`src/secagent/telemetry/`)
- [ ] Subsystem 3: Dynamic Scenario Synthesizer & Fuzzer (`src/secagent/generator/`)
- [ ] Subsystem 4: Invariant Verification Engine (`src/secagent/engine/`)
- [ ] Subsystem 5: GitHub Action & Developer CLI (`action.yml`, `src/secagent/cli.py`, `app.py`)

## OWASP Coverage
<!-- Check which OWASP category this PR impacts, if applicable -->
- [ ] ASI01: Agent Goal Hijack
- [ ] ASI02: Tool Misuse & Parameter Exploitation
- [ ] ASI03: Identity & Privilege Abuse
- [ ] ASI05: Unexpected Code Execution (RCE)
- [ ] ASI06: Context Poisoning / Scope Abuse
- [ ] ASI08: Cascading Failures / Infinite Loops
- [ ] ASI10: Rogue Agent Egress Exfiltration

## Quality Checklist
- [ ] Local tests pass (`pytest tests/ -v`)
- [ ] Linter checks pass (`ruff check .`)
- [ ] Code formatting verified (`ruff format --check .`)
- [ ] Does not break schema contracts (`schemas/trace_event.schema.json`)
