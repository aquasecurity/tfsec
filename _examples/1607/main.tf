resource "aws_instance" "non_compliant" {
  ami           = "ami-1234"
  instance_type = "t2.small"

  tags = {
    Department = "Finance"
  }

}