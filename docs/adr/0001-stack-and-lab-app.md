# ADR-0001 — Stack: Node.js 20 + Express, own minimal vulnerable app

- **Status:** Accepted · **Date:** 2026-08-23 · **Deciders:** Security Engineering

## Context
The test allows a free stack and either a known vulnerable app (Juice Shop, DVWA) or
a minimal own build for the VAPT. We must demonstrate the 10 specific CWE classes and
remediate ≥8 **in our own code** with paired malicious/legitimate tests.

## Decision
Build a minimal Express (Node 20) app with a `/vuln` lab surface (the 10 CWE) and a
`/secure` remediated twin. Use pure-JS dependencies (`sql.js` WASM SQLite, no native
build) to keep the Docker image slim and the pipeline fast.

## Consequences
- (+) We control the exact 10 CWE; every PoC and every fix is reproducible and unit-tested (20/20).
- (+) Remediation lives in our code (rubric rewards this over patching third-party apps).
- (+) `docker compose up` is a single fast command (Bonus +5%).
- (−) A hand-built lab must be transparently documented (e.g. the XXE parser is deliberately naive) — noted in README and the finding.
- (−) Not a "famous" target; mitigated by mapping every finding to OWASP/CWE and offering Juice Shop as an optional comparison bank.
