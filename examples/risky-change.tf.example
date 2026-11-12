# A risky change, for trying out the plan check. See Part 14 of MANUAL.md.
#
# It looks reasonable: the reporting team wants to query the card database from the
# office network, and needs a key for their exports. It breaks two rules:
#   PLAN-02  it lets an address range into the card data zone
#   PLAN-04  it creates an encryption key with rotation off
#
# To try it, copy this file into the terraform folder as risky-change.tf, run
# 'secuguard plan-check', then delete the copy.

resource "aws_vpc_security_group_ingress_rule" "risky_office_to_card_database" {
  security_group_id = aws_security_group.tier["cde"].id
  cidr_ipv4         = "10.20.30.0/24"
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  description       = "Reporting team queries from the office network"
}

resource "aws_kms_key" "risky_reports" {
  description             = "Key for reporting exports"
  enable_key_rotation     = false
  deletion_window_in_days = 7

  tags = { Name = "secuguard-reports" }
}
