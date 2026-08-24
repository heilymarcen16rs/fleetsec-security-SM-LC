# Threat Intelligence — FleetSec Breach INC-2026-001

## A. Indicators of Compromise (IOCs) — extracted from the timeline

| # | Type | Indicator | First seen (UTC) | Context in this incident |
|---|------|-----------|------------------|--------------------------|
| 1 | IPv4 | `185.220.101.22` | T+00:00 | Console login source (Tor) **and** exfil destination (T+01:10) |
| 2 | IAM user | `svc-monitoring` | T+00:15 | Service account abused; CreateLoginProfile → AttachUserPolicy admin |
| 3 | Docker image | `docker.io/attacker/exfil:latest` | T+01:40 | Malicious task registered in ECS (`RegisterTaskDefinition`) |
| 4 | EC2 instance | `i-0abc1234def56789` | T+01:50 | GuardDuty `Trojan:EC2/DNSDataExfiltration` |
| 5 | Internal IP | `10.0.2.45` | T+01:10 | Compromised host, source of 49 GB outbound in VPC Flow Logs |
| 6 | KMS key | `prod-data-key` | T+00:58 | 12× `kms:Decrypt` to read encrypted driver data |
| 7 | S3 bucket | `fleetpay-prod-drivers` | T+00:35 | 387× GetObject / 8 min → 45.7 GB exfiltrated |
| 8 | ASN | `AS213151` | T+00:00 | Owner of 185.220.101.22 (Tor infrastructure) |

### Behavioral patterns (higher on the Pyramid of Pain — prefer these detections)
- **Volume/velocity**: 387 S3 GetObject in 8 min (~48/min) against a single bucket by one principal.
- **Timing**: privilege escalation (AttachUserPolicy admin) at off-hours.
- **Sequence**: ConsoleLogin(Tor) → CreateLoginProfile → AttachUserPolicy → bulk GetObject → kms:Decrypt → egress → RegisterTaskDefinition(attacker image) → DeleteTrail → DNS exfil.

## Enrichment (VirusTotal / AbuseIPDB / Shodan / MISP-OTX — free tier)

> Run the commands below with your own free-tier API keys. Expected profile for
> `185.220.101.22` is a **known Tor exit node** (AS213151, Hetzner-adjacent Tor
> infra), historically flagged for abuse — high-confidence malicious for a
> production admin login.

```bash
# AbuseIPDB (free tier)
curl -s -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=185.220.101.22" -d maxAgeInDays=90 \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq '.data.abuseConfidenceScore, .data.isTor, .data.countryCode'

# VirusTotal (free tier)
curl -s https://www.virustotal.com/api/v3/ip_addresses/185.220.101.22 \
  -H "x-apikey: $VT_KEY" | jq '.data.attributes.last_analysis_stats, .data.attributes.as_owner'

# Shodan (free tier)
curl -s "https://api.shodan.io/shodan/host/185.220.101.22?key=$SHODAN_KEY" | jq '.org, .ports, .tags'

# Tor exit list cross-check (authoritative, no key needed)
curl -s https://check.torproject.org/torbulkexitlist | grep -x 185.220.101.22 && echo "CONFIRMED Tor exit node"
```

Record results in this table:

| Source | Verdict | Score / detail |
|--------|---------|----------------|
| AbuseIPDB | (fill) | confidence __ / isTor: true |
| VirusTotal | (fill) | malicious __ / AS213151 |
| Shodan | (fill) | org / open ports |
| Tor exit list | Confirmed Tor exit | — |

## B. Load the IOCs into GuardDuty (Threat Intel Set)

The IOC file `fleetsec-iocs.txt` (one IP per line) is deployed two ways.

### Option 1 — Terraform (preferred, in-repo, auditable)
Already wired in `terraform/environments/prod/main.tf`:
`aws_s3_object.threat_intel` uploads the file to the immutable logs bucket and
`aws_guardduty_threatintelset.fleetsec` registers it. Apply with:

```bash
cd terraform/environments/prod
terraform apply -target=aws_guardduty_threatintelset.fleetsec
```

### Option 2 — AWS CLI (manual / emergency)
```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
BUCKET=fleetsec-logs-<account_id>

# 1. Upload the list to the immutable evidence bucket
aws s3 cp detection/threat-intel/fleetsec-iocs.txt s3://$BUCKET/threat-intel/fleetsec-iocs.txt

# 2. Register the Threat Intel Set (TXT format, one IP per line)
aws guardduty create-threat-intel-set \
  --detector-id "$DETECTOR_ID" \
  --name fleetsec-iocs \
  --format TXT \
  --location "https://s3.amazonaws.com/$BUCKET/threat-intel/fleetsec-iocs.txt" \
  --activate

# 3. Verify
aws guardduty list-threat-intel-sets --detector-id "$DETECTOR_ID"
```

Any future GuardDuty finding whose remote IP matches the set is raised as
`UnauthorizedAccess:*/MaliciousIPCaller.Custom` and routed to SNS (see
`monitoring.tf` EventBridge rule for severity ≥ 7).
