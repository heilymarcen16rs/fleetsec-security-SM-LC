# ADR-0002 — DevSecOps quality gates and thresholds

- **Status:** Accepted · **Date:** 2026-08-23 · **Deciders:** Security Engineering

## Context
The pipeline must enforce hard gates (SAST, SCA, DAST, container, IaC, secrets) yet the
repo intentionally contains a vulnerable lab. A naive "0 findings" gate would either
fail permanently or force us to delete the teaching material.

## Decision
Two-tier SAST: an **informational** Semgrep run over the whole repo (shows the custom
rules firing, non-blocking) plus a **blocking** gate over production code only
(`app/src`, excluding `vulnerable.js` and tests), with inline `nosemgrep`
suppressions carrying `razón · fecha · responsable` for the V-10 lab secret.
Thresholds: SCA blocks HIGH/CRITICAL (≈ CVSS ≥8 direct / ≥9 indirect), container
blocks CRITICAL, DAST HIGH/CRITICAL block + MEDIUM opens a `security/medium` issue,
Checkov hard-fails (built-in CKV_AWS_24/25 enforce the admin-port rule). Independent
jobs run in parallel with npm/Trivy caches to stay ≤15 min.

## Consequences
- (+) Gate reflects real production risk; suppressions are auditable (mirrors the required SAST discipline).
- (+) Custom rules are still demonstrably exercised.
- (+) Parallel fan-out + caching meets the ≤15-min SLA.
- (−) The exclusion list must be reviewed so it never hides a real production finding — owned by SecOps in CODEOWNERS.
