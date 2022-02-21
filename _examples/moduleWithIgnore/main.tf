




#tfsec:ignore:AWS052:exp:2025-02-02
module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 2.0"

  identifier = "demodb"

  engine            = "mysql"
  engine_version    = "5.7.19"
  instance_class    = "db.t2.large"
  allocated_storage = 5

  name     = "demodb"
  username = "user"
  password = aws_ssm_parameter.pw.value
  port     = "3306"

  maintenance_window = "Mon:00:00-Mon:03:00"
  backup_window      = "03:00-06:00"
}

resource "aws_ssm_parameter" "pw" {
  name  = "pw"
  type  = "SecureString"
  value = "changeme"
}
