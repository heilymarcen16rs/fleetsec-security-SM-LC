#!/usr/bin/env bash
# Creates an ATOMIC Conventional-Commits history for the FleetSec deliverable.
# Run once from the repo root:  bash scripts/init-git-history.sh
# Commits are authored under YOUR git identity (git config user.name/email).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -d .git ]; then
  echo "A .git already exists here. Aborting so we don't rewrite history."
  exit 1
fi

git init -q
git config core.autocrlf false
: "${GIT_AUTHOR_NAME:=$(git config user.name || echo '')}"
if [ -z "$(git config user.name || true)" ]; then
  echo "!! Set your identity first:  git config user.name 'Tu Nombre'; git config user.email 'tu@correo'"; exit 1
fi

c(){ git add -A -- "${@:2}" >/dev/null; GIT_COMMITTER_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" git commit -q -m "$1"; echo "  ✓ $1"; }

# 1. tooling / scaffold
c "chore: scaffold repo, gitignore, pre-commit hooks and CODEOWNERS" .gitignore .pre-commit-config.yaml CODEOWNERS .gitleaks.toml docker-compose.yml scripts/init-git-history.sh scripts/md_to_pdf.py
# 2-3 app base
c "feat(app): minimal Express telemetry API (health, app factory, server)" app/package.json app/package-lock.json app/src/app.js app/src/server.js app/src/config.js app/.dockerignore
c "feat(app): in-memory SQLite datastore with seed, logger, pii, jwt libs" app/src/lib app/data
# 4 vulnerable lab
c "feat(vuln): deliberately vulnerable VAPT lab endpoints V-01..V-10" app/src/routes/vulnerable.js
# 5 PoC tests
c "test(vapt): PoC suite proving all 10 findings are exploitable" app/tests/vapt.poc.test.js
# 6 remediations (secure twin) + regression tests
c "fix(security): remediate V-01..V-10 on the /secure surface (parameterized SQL, JWT allowlist, SSRF/XXE/traversal guards, DTO allowlist, rate limit, PII masking, IDOR ownership, secrets to env)" app/src/routes/secure.js app/openapi.yaml
c "test(security): remediation regression suite (malicious->reject, legit->ok)" app/tests/remediation.test.js
# 7 container
c "feat(app): hardened multi-stage Dockerfile (pinned base, non-root)" app/Dockerfile
# 8 SAST rules
c "feat(sast): custom Semgrep taint rules for the Node/Express stack" semgrep/fleetsec-rules.yaml
# 9 pipeline
c "feat(ci): DevSecOps pipeline (SAST/SCA/SBOM/DAST/image/IaC/secrets) and break-glass" .github/workflows
# 10 IaC
c "feat(iac): Terraform security-baseline module (VPC/KMS/S3/RDS/IAM/monitoring/WAF)" terraform/modules
c "feat(iac): prod environment, GuardDuty threat-intel set and Checkov custom policy" terraform/environments checkov
# 11 detection & IR
c "feat(detection): Sigma rules, threat-intel enrichment and NIST IR playbook" detection
# 12 docs
c "docs: README, master doc, ADRs, diagrams, compliance matrix, AI report, sprints, video script" README.md DOCUMENTO-MAESTRO.md DOCUMENTO-MAESTRO.pdf docs
c "docs(vapt): VAPT report (markdown + PDF)" vapt

echo "Done. Atomic history created:"
git --no-pager log --oneline
