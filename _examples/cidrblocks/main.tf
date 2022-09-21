resource "aws_security_group" "example_security_group_compliance" {
  name = "example_security_group_compliance"

  description = "Example SG"

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["1.2.3.4", "5.6.7.8"]
  }

}

resource "aws_security_group" "example_security_group_non_compliance" {
  name = "example_security_group_non_compliance"

  description = "Example SG"

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["1.2.3.4", "1.6.7.8"]
  }

}