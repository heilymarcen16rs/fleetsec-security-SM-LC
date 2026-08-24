# ADR-0005 — Handling the "traps" embedded in the test requirements

- **Status:** Accepted · **Date:** 2026-08-23 · **Deciders:** Security Engineering

## Context
Several requirements are deliberately worded to tempt an insecure or non-compliant
implementation. A senior engineer must detect them and correct rather than comply
blindly. This ADR records each trap and the professional decision taken. Full analysis
in `README.md` §"Análisis crítico y trampas".

## Decision (trap → resolution)
1. **KMS "key policy sin Principal AWS *"** — a wildcard `Principal:"*"` on a key policy
   is dangerous. We used the account-root admin statement + scoped service principals
   (never `Principal:"*"`). See `kms.tf`.
2. **SG "0.0.0.0/0 excepto 80/443 en ALB"** — only the ALB SG exposes 0.0.0.0/0, only on
   80 (redirect) and 443; admin ports never. Enforced by CKV_AWS_24/25.
3. **RDS `ssl=1` / `log_connections=1`** — implemented via a parameter group
   (`rds.force_ssl=1`, `log_connections=1`), plus IAM auth and no public endpoint.
4. **V-10 "migrar a variable de entorno o gestor de secretos — nunca mover a otro
   archivo del repo"** — moving a secret to another repo file is the trap; we removed it
   to env/Secrets Manager. See `secure.js` / `rds.tf`.
5. **DAST "cobertura ≥80% del OpenAPI"** — we ship an OpenAPI spec of the *secure*
   surface so ZAP has a real contract to authenticate against.
6. **Break-glass** — must be audited: 2 reviewers via a protected Environment + an
   auto-opened CRITICAL issue on every override (`break-glass.yml`).
7. **AI report** — must **admit** at least one AI hallucination; hiding it scores zero.
   Documented honestly in `docs/ai-report.md`.
8. **`svc-monitoring` service account with console login** — service accounts must not
   have console access; the IR plan revokes it and the P1 backlog adds an SCP.

## Consequences
- (+) Demonstrates security judgment over literal compliance — the core of the evaluation.
- (+) Each correction is traceable to code/evidence.
- (−) A reviewer expecting literal compliance may need the rationale — hence this ADR and the README section.
