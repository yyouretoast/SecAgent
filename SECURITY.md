# Security Policy

## Supported Versions

SecAgent is currently in pre-1.0 (`0.1.x`) development on the `main` branch. Security fixes are applied to `main`.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities in SecAgent itself (such as path traversal, sandbox escapes, or policy bypasses in the scanner).

1. Use GitHub's private **Security Advisories** feature (`Security` → `Advisories` → `Report a vulnerability` on `yyouretoast/SecAgent`).
2. Include a minimal reproduction trace, policy file, or CLI invocation and the expected vs. observed behavior.
3. Maintainers will acknowledge reports within 72 hours and coordinate a fix before public disclosure.

## Deployment Scope

`secagent serve` launches a single-user local developer dashboard bound to `127.0.0.1`. Do not expose it on public interfaces or behind an unauthenticated reverse proxy, as its sidebar inputs are designed for inspecting local report and trace JSON files.
