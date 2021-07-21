resource "aws_instance" "compliant" {

  count = terraform.workspace == "default" ? 5 : 20

  ami            = "ami-12345"
  instance_type  = "t2.small"
  cpu_core_count = 4

  tags = {
    Department = "Finance"
    CostCentre = "CC1234"
  }
}
