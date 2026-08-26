#!/usr/bin/env python3
"""Genera el diagrama de arquitectura objetivo de FleetSec con iconos reales de AWS."""
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.network import CloudFront, ELB, VPC
from diagrams.aws.compute import ECS
from diagrams.aws.database import RDS
from diagrams.aws.storage import S3
from diagrams.aws.security import WAF, Guardduty, SecretsManager, SecurityHub
from diagrams.aws.management import Cloudtrail
from diagrams.onprem.client import Users

graph_attr = {
    "fontname": "Helvetica",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "spline",
    "nodesep": "0.6",
    "ranksep": "0.9",
    "fontsize": "11",
}
node_attr = {"fontname": "Helvetica", "fontsize": "10"}
edge_attr = {"fontname": "Helvetica", "fontsize": "9", "color": "#33454f"}

with Diagram(
    "FleetSec — Arquitectura de Seguridad Objetivo",
    filename="/home/claude/fleetsec-security/docs/diagrams/architecture-target",
    show=False,
    outformat="png",
    direction="TB",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):
    usuarios = Users("Conductor / Despachador\ny Operador de Seguridad")

    with Cluster("Internet — No confiable"):
        edge_public = CloudFront("CloudFront")
        waf = WAF("WAF v2\nSQLi · BadInputs\nRateLimit · Geo CO/PE/US")

    with Cluster("VPC · Subred pública (2 AZ)"):
        alb = ELB("ALB :443\nTLS 1.2+ · ACM")

    with Cluster("VPC · Subred de aplicación (privada)"):
        ecs = ECS("ECS Fargate :8080\nNode 20 · non-root\nrol IAM")

    with Cluster("VPC · Subred de datos (privada, sin NAT)"):
        rds = RDS("RDS PostgreSQL\nMulti-AZ · CMK\nsin acceso público")
        s3 = S3("S3 Telemetría\nSSE-KMS · BPA")
        sm = SecretsManager("Secrets Manager\nrotación 30d")

    with Cluster("Seguridad y Observabilidad"):
        gd = Guardduty("GuardDuty\n+ Threat Intel Set")
        ct = Cloudtrail("CloudTrail\nmultirregión + Object Lock")
        sh = SecurityHub("Security Hub\nFSBP + CIS 1.4")

    usuarios >> Edge(label="HTTPS · JWT / SSO+MFA") >> edge_public
    edge_public >> Edge(label="reglas gestionadas") >> waf
    waf >> Edge(label="HTTPS firmado") >> alb
    alb >> Edge(label="HTTPS · solo SG-app") >> ecs
    ecs >> Edge(label="TLS · IAM auth") >> rds
    ecs >> Edge(label="TLS · VPC endpoint") >> s3
    ecs >> Edge(label="GetSecretValue · KMS") >> sm
    ecs >> Edge(style="dashed", label="logs / métricas") >> ct
    s3 >> Edge(style="dashed", label="eventos de datos") >> ct
    rds >> Edge(style="dashed", label="hallazgos") >> gd
    ct >> Edge(style="dashed") >> sh
    gd >> Edge(style="dashed") >> sh

print("architecture-target.png generado")
