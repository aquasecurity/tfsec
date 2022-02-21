resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main"
  }
}


resource "aws_security_group" "foo" {
  name        = "example"
  description = "Some SG" # we don't care about this
  vpc_id      = aws_vpc.main.id
}



resource "aws_security_group" "example" {
  name        = "example"
  description = "Some SG" # we don't care about this
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "access from xyz" # this description is the important one
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.foo.id]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.foo.id]
  }
}
