locals {
  rules = {
    http  = 80
    https = 443
  }
}

resource "aws_security_group" "this" {
  name        = "Test"
  description = "test sg"
  vpc_id      = "vpc-7238923ye8723t8"
}

# tfsec:ignore:aws-vpc-no-public-ingress-sgr[from_port=443]
resource "aws_security_group_rule" "this" {
  for_each    = local.rules
  type        = "ingress"
  description = "test"
  from_port   = each.value
  to_port     = each.value
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.this.id
}