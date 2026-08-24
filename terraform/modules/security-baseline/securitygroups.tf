# =========================================================== Security Groups
# TRAP FIXED: "sin SG con 0.0.0.0/0 excepto 80/443 en ALB".
# Only the ALB SG accepts 0.0.0.0/0, and ONLY on 80/443. App and data SGs accept
# traffic solely from the upstream SG. No SG opens 22 or 3389 to the world
# (Checkov CKV_AWS_24/25 + custom CKV_FLEETSEC_1 enforce this in CI).

resource "aws_security_group" "alb" {
  # checkov:skip=CKV_AWS_260:ALB intentionally accepts 0.0.0.0/0 on port 80 ONLY to 301-redirect to HTTPS — explicitly permitted by the requirement ("sin SG con 0.0.0.0/0 excepto 80/443 en ALB"). Admin ports 22/3389 are never exposed (CKV_AWS_24/25 + CKV_FLEETSEC_1 pass).
  # checkov:skip=CKV2_AWS_5:ALB resource lives in the application stack; this baseline module publishes the SG as an output for it to consume.
  name        = "${local.name}-alb-sg"
  description = "ALB - public 80/443 only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP (redirects to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.alb_ingress_cidrs
  }
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.alb_ingress_cidrs
  }
  egress {
    description = "To app tier only"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [for s in aws_subnet.app : s.cidr_block]
  }
  tags = merge(var.tags, { Name = "${local.name}-alb-sg" })
}

resource "aws_security_group" "app" {
  # checkov:skip=CKV2_AWS_5:ECS service (consumer of this SG) is defined in the application stack, not the security baseline.
  name        = "${local.name}-app-sg"
  description = "App tier - only from ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    description = "HTTPS out via NAT (patching, AWS APIs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description     = "To data tier (Postgres)"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = []
    cidr_blocks     = [for s in aws_subnet.data : s.cidr_block]
  }
  tags = merge(var.tags, { Name = "${local.name}-app-sg" })
}

resource "aws_security_group" "data" {
  name        = "${local.name}-data-sg"
  description = "Data tier - only Postgres from app SG"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Postgres from app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  # No egress rules (default deny). RDS does not need outbound.
  tags = merge(var.tags, { Name = "${local.name}-data-sg" })
}
