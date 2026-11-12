# The network is split into three tiers. The tag secuguard:pci-scope records which
# PCI DSS scope category each tier belongs to. Later stages check that reality still
# matches these tags.
#
#   cde        Cardholder data environment. Systems that store, process, or transmit card data.
#   shared     Connected systems. They can reach the CDE, so they are in scope too.
#   corporate  Out of scope. No path to the CDE.

locals {
  scope_tag = "secuguard:pci-scope"

  tiers = {
    cde       = { scope = "cde", first_subnet = 10 }
    shared    = { scope = "connected", first_subnet = 20 }
    corporate = { scope = "out-of-scope", first_subnet = 30 }
  }

  # Two availability zones, because the load balancer added in stage 2 needs two.
  zones = slice(data.aws_availability_zones.available.names, 0, 2)

  subnets = merge([
    for tier_name, tier in local.tiers : {
      for index, zone in local.zones :
      "${tier_name}-${substr(zone, -1, 1)}" => {
        tier  = tier_name
        scope = tier.scope
        zone  = zone
        cidr  = cidrsubnet(var.vpc_cidr, 8, tier.first_subnet + index)
      }
    }
  ]...)
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "secuguard-vpc" }
}

resource "aws_subnet" "tier" {
  for_each = local.subnets

  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.zone

  tags = {
    Name              = "secuguard-${each.key}"
    (local.scope_tag) = each.value.scope
  }
}

# One route table per tier with no routes beyond the VPC itself. Nothing here can
# reach the internet. There is no internet gateway and no NAT gateway.
resource "aws_route_table" "tier" {
  for_each = local.tiers

  vpc_id = aws_vpc.main.id

  tags = {
    Name              = "secuguard-${each.key}"
    (local.scope_tag) = each.value.scope
  }
}

resource "aws_route_table_association" "tier" {
  for_each = local.subnets

  subnet_id      = aws_subnet.tier[each.key].id
  route_table_id = aws_route_table.tier[each.value.tier].id
}

# AWS creates a default security group in every VPC that allows all traffic between
# its members. Taking it over with no rules closes that door.
resource "aws_default_security_group" "locked" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "secuguard-default-locked" }
}

resource "aws_security_group" "tier" {
  for_each = local.tiers

  name        = "secuguard-${each.key}"
  description = "SecuGuard ${each.key} tier"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name              = "secuguard-${each.key}"
    (local.scope_tag) = each.value.scope
  }
}

# The only way into the CDE: HTTPS from the shared services tier.
resource "aws_vpc_security_group_ingress_rule" "cde_from_shared" {
  security_group_id            = aws_security_group.tier["cde"].id
  referenced_security_group_id = aws_security_group.tier["shared"].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "HTTPS from shared services"
}

# Corporate can reach shared services, but has no rule into the CDE.
resource "aws_vpc_security_group_ingress_rule" "shared_from_corporate" {
  security_group_id            = aws_security_group.tier["shared"].id
  referenced_security_group_id = aws_security_group.tier["corporate"].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "HTTPS from corporate"
}
