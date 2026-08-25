# Inteligencia de Amenazas — Brecha FleetSec INC-2026-001

## A. Indicadores de Compromiso (IOCs) — extraídos de la cronología

| # | Tipo | Indicador | Primera detección (UTC) | Contexto en este incidente |
|---|------|-----------|------------------|--------------------------|
| 1 | IPv4 | `185.220.101.22` | T+00:00 | Origen del inicio de sesión en consola (Tor) **y** destino de exfiltración (T+01:10) |
| 2 | Usuario IAM | `svc-monitoring` | T+00:15 | Cuenta de servicio abusada; CreateLoginProfile → AttachUserPolicy admin |
| 3 | Imagen Docker | `docker.io/attacker/exfil:latest` | T+01:40 | Tarea maliciosa registrada en ECS (`RegisterTaskDefinition`) |
| 4 | Instancia EC2 | `i-0abc1234def56789` | T+01:50 | GuardDuty `Trojan:EC2/DNSDataExfiltration` |
| 5 | IP interna | `10.0.2.45` | T+01:10 | Host comprometido, origen de 49 GB salientes en los VPC Flow Logs |
| 6 | Clave KMS | `prod-data-key` | T+00:58 | 12× `kms:Decrypt` para leer datos cifrados de conductores |
| 7 | Bucket S3 | `fleetpay-prod-drivers` | T+00:35 | 387× GetObject / 8 min → 45.7 GB exfiltrados |
| 8 | ASN | `AS213151` | T+00:00 | Propietario de 185.220.101.22 (infraestructura Tor) |

### Patrones de comportamiento (más arriba en la Pirámide del Dolor — preferir estas detecciones)
- **Volumen/velocidad**: 387 GetObject de S3 en 8 min (~48/min) contra un único bucket por un solo principal.
- **Momento**: escalada de privilegios (AttachUserPolicy admin) fuera de horario.
- **Secuencia**: ConsoleLogin(Tor) → CreateLoginProfile → AttachUserPolicy → GetObject masivo → kms:Decrypt → salida → RegisterTaskDefinition(imagen del atacante) → DeleteTrail → exfiltración DNS.

## Enriquecimiento (VirusTotal / AbuseIPDB / Shodan / MISP-OTX — capa gratuita)

> Ejecute los comandos siguientes con sus propias claves de API de capa gratuita. El perfil
> esperado para `185.220.101.22` es un **nodo de salida Tor conocido** (AS213151,
> infraestructura Tor adyacente a Hetzner), históricamente señalado por abuso — malicioso
> con alta confianza para un inicio de sesión de administración en producción.

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

Registre los resultados en esta tabla:

| Fuente | Veredicto | Puntaje / detalle |
|--------|---------|----------------|
| AbuseIPDB | (completar) | confidence __ / isTor: true |
| VirusTotal | (completar) | malicious __ / AS213151 |
| Shodan | (completar) | org / puertos abiertos |
| Lista de salidas Tor | Salida Tor confirmada | — |

## B. Cargar los IOCs en GuardDuty (Threat Intel Set)

El archivo de IOCs `fleetsec-iocs.txt` (una IP por línea) se despliega de dos maneras.

### Opción 1 — Terraform (preferido, en el repositorio, auditable)
Ya está conectado en `terraform/environments/prod/main.tf`:
`aws_s3_object.threat_intel` sube el archivo al bucket de logs inmutable y
`aws_guardduty_threatintelset.fleetsec` lo registra. Aplique con:

```bash
cd terraform/environments/prod
terraform apply -target=aws_guardduty_threatintelset.fleetsec
```

### Opción 2 — AWS CLI (manual / emergencia)
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

Cualquier hallazgo futuro de GuardDuty cuya IP remota coincida con el conjunto se genera como
`UnauthorizedAccess:*/MaliciousIPCaller.Custom` y se enruta a SNS (véase la regla de
EventBridge en `monitoring.tf` para severidad ≥ 7).
