resource "aws_security_group" "ec2_dns" {
  count = var.sec_count ? 1 : 0

  vpc_id = "1"

}

resource "aws_instance" "test_instance" {
  ami           = "test-1234"
  instance_type = "t2-small"

  security_groups = [length(aws_security_group.ec2_dns) > 0 ? aws_security_group.ec2_dns[0].id : ""]
}

variable "sec_count" {
  default = false
}