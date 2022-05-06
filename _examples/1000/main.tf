
variable "bad" {
  default = "0.0"
}

resource "aws_security_group" "test" {
  name        = "allow-all-sg"
  description = "Allowing everyone to connect to this public instance"
  vpc_id      = aws_vpc.my_vpc.id
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = "22"
    to_port     = "22"
    protocol    = "tcp"
  }
  tags = {
    Type = "Public"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.${var.bad}/0"]
  }
}
