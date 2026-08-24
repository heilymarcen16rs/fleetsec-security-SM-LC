# ADR-0004 — Detection engineering & incident response approach

- **Status:** Accepted · **Date:** 2026-08-23 · **Deciders:** Security Engineering

## Context
Entregable 04 provides a fully-embedded breach timeline. We must produce IOCs,
detections, an IR playbook, MITRE mapping, RCA and executive comms.

## Decision
Prioritise detections high on the **Pyramid of Pain** (behaviours/TTPs over IPs):
4 Sigma rules (IAM admin off-hours, DeleteTrail anti-forensics CRITICAL, SQLi in app
logs, bulk S3 GetObject). Load IOCs into a GuardDuty **Threat Intel Set** via Terraform
(preferred) with an AWS CLI fallback. IR follows NIST 800-61 (preserve→contain→
eradicate→recover→lessons) with exact reversible AWS CLI, MITRE ATT&CK v14 (8
techniques), 5-Whys + Swiss-cheese RCA, a ≤1-page CEO brief, and the Ley 1581 SIC
notification path (15 business days).

## Consequences
- (+) Rules validated with `pysigma` (parse-clean, 4/4). A DeleteTrail *attempt* alerts even when SCP blocks it.
- (+) Threat Intel Set is version-controlled and reproducible.
- (−) Sigma aggregation syntax (bulk GetObject) is backend-specific — documented; translate with `sigma convert`.
- (−) IP-based IOCs (185.220.101.22) age fast — re-evaluate every 90 days; behavioural rules carry the load.
