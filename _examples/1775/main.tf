module "ssh_server_sg" {
  source = "terraform-aws-modules/security-group/aws//modules/ssh"
  name    = "ssh-server"
  description = "Security group for ssh-server with SSH ports open within VPC"
  vpc_id   = "vpc-12345678"
  ingress_cidr_blocks = ["0.0.0.0/0"]
}