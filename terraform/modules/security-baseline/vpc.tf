# =========================================================== VPC (3-tier, 2 AZs)
# public / app / data subnets. Data tier has NO route to NAT (no egress).
# NACLs restrict the data subnet. VPC Flow Logs -> S3 + CloudWatch.

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${local.name}-igw" })
}

# Lock down the VPC default security group (CIS 5.4 / CKV2_AWS_12): no rules.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # intentionally no ingress/egress -> denies all traffic
  tags = merge(var.tags, { Name = "${local.name}-default-locked" })
}

# --- Subnets: 2 public, 2 app, 2 data --------------------------------------
resource "aws_subnet" "public" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = var.azs[count.index]
  # No auto-assign public IP; ALB gets its own ENI. (CIS 5.x)
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${local.name}-public-${count.index}", Tier = "public" })
}

resource "aws_subnet" "app" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = var.azs[count.index]
  tags              = merge(var.tags, { Name = "${local.name}-app-${count.index}", Tier = "app" })
}

resource "aws_subnet" "data" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)
  availability_zone = var.azs[count.index]
  tags              = merge(var.tags, { Name = "${local.name}-data-${count.index}", Tier = "data" })
}

# --- NAT for app tier only --------------------------------------------------
resource "aws_eip" "nat" {
  count  = length(var.azs)
  domain = "vpc"
  tags   = var.tags
}

resource "aws_nat_gateway" "nat" {
  count         = length(var.azs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(var.tags, { Name = "${local.name}-nat-${count.index}" })
  depends_on    = [aws_internet_gateway.igw]
}

# --- Route tables -----------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = merge(var.tags, { Name = "${local.name}-rt-public" })
}

resource "aws_route_table_association" "public" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "app" {
  count  = length(var.azs)
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }
  tags = merge(var.tags, { Name = "${local.name}-rt-app-${count.index}" })
}

resource "aws_route_table_association" "app" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app[count.index].id
}

# Data tier route table: NO 0.0.0.0/0 route (isolated, no internet egress).
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${local.name}-rt-data" })
}

resource "aws_route_table_association" "data" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

# --- Restrictive NACL on the data subnet ------------------------------------
resource "aws_network_acl" "data" {
  # checkov:skip=CKV2_AWS_1:False positive — this NACL is explicitly attached via subnet_ids below.
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.data[*].id
  # Inbound: only Postgres from the app subnets.
  dynamic "ingress" {
    for_each = aws_subnet.app
    content {
      protocol   = "tcp"
      rule_no    = 100 + ingress.key
      action     = "allow"
      cidr_block = ingress.value.cidr_block
      from_port  = 5432
      to_port    = 5432
    }
  }
  # Ephemeral return traffic to the app subnets.
  dynamic "egress" {
    for_each = aws_subnet.app
    content {
      protocol   = "tcp"
      rule_no    = 100 + egress.key
      action     = "allow"
      cidr_block = egress.value.cidr_block
      from_port  = 1024
      to_port    = 65535
    }
  }
  tags = merge(var.tags, { Name = "${local.name}-nacl-data" })
}

# --- VPC endpoints so data/app tiers reach AWS without internet -------------
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat([aws_route_table.data.id], aws_route_table.app[*].id)
  tags              = merge(var.tags, { Name = "${local.name}-vpce-s3" })
}

# --- VPC Flow Logs -> CloudWatch (and S3) -----------------------------------
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/${local.name}/vpc/flowlogs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.s3.arn
  tags              = var.tags
}

resource "aws_iam_role" "flow" {
  name = "${local.name}-flowlogs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "flow" {
  name = "${local.name}-flowlogs-policy"
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"
      ],
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  iam_role_arn    = aws_iam_role.flow.arn
  log_destination = aws_cloudwatch_log_group.flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
  tags            = var.tags
}
