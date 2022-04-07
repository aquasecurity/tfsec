
module "application_db" {
  source = "./database"
}

# tfsec:ignore:aws-rds-enable-performance-insights-encryption
resource "aws_db_instance" "toplevel_db" {
  apply_immediately            = true
  identifier                   = "${var.platform_name}-toplevel-db"
  availability_zone            = "${data.aws_region.current.name}a"
  username                     = "awsrdsdba"
  allocated_storage            = 20
  password                     = var.db_admin_password
  engine                       = "postgres"
  engine_version               = "14.2"
  multi_az                     = false
  instance_class               = "db.t3.micro"
  db_subnet_group_name         = aws_db_subnet_group.db_subnet_group.id
  backup_window                = "00:00-00:30"
  maintenance_window           = "sat:01:00-sat:02:00"
  backup_retention_period      = 7
  storage_encrypted            = true
  vpc_security_group_ids       = [aws_security_group.db_security_group.id]
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${var.platform_name}-final-snapshot"
  allow_major_version_upgrade  = true
  auto_minor_version_upgrade   = true
  publicly_accessible          = false
  copy_tags_to_snapshot        = true
  performance_insights_enabled = true
}