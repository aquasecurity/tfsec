package rds

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSRDSRetentionPeriod(t *testing.T) {
	expectedCode := "aws-rds-specify-backup-retention"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "db instance with default retention fails check",
			source: `
		 			resource "aws_db_instance" "bad_example" {
		 				allocated_storage    = 10
		 				engine               = "mysql"
		 				engine_version       = "5.7"
		 				instance_class       = "db.t3.micro"
		 				name                 = "mydb"
		 				username             = "foo"
		 				password             = "foobarbaz"
		 				parameter_group_name = "default.mysql5.7"
		 				skip_final_snapshot  = true
		 			}
		 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rds cluster with default retention fails check",
			source: `
		 			resource "aws_rds_cluster" "bad_example" {
		 				cluster_identifier      = "aurora-cluster-demo"
		 				engine                  = "aurora-mysql"
		 				engine_version          = "5.7.mysql_aurora.2.03.2"
		 				availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
		 				database_name           = "mydb"
		 				master_username         = "foo"
		 				master_password         = "bar"
		 				preferred_backup_window = "07:00-09:00"
		 			}
		 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "db instance with explicit retention of 1 fails check",
			source: `
		 			resource "aws_db_instance" "bad_example" {
		 				allocated_storage    = 10
		 				engine               = "mysql"
		 				engine_version       = "5.7"
		 				instance_class       = "db.t3.micro"
		 				name                 = "mydb"
		 				username             = "foo"
		 				password             = "foobarbaz"
		 				parameter_group_name = "default.mysql5.7"
		 				backup_retention_period = 1
		 				skip_final_snapshot  = true
		 			}
		 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rds cluster with explicit retention of 1 fails check",
			source: `
		 			resource "aws_rds_cluster" "bad_example" {
		 				cluster_identifier      = "aurora-cluster-demo"
		 				engine                  = "aurora-mysql"
		 				engine_version          = "5.7.mysql_aurora.2.03.2"
		 				availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
		 				database_name           = "mydb"
		 				master_username         = "foo"
		 				master_password         = "bar"
		 				backup_retention_period = 1
		 				preferred_backup_window = "07:00-09:00"
		 			}
		 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "rds cluster with retention greater than default passes check",
			source: `
		 			resource "aws_rds_cluster" "good_example" {
		 				cluster_identifier      = "aurora-cluster-demo"
		 				engine                  = "aurora-mysql"
		 				engine_version          = "5.7.mysql_aurora.2.03.2"
		 				availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
		 				database_name           = "mydb"
		 				master_username         = "foo"
		 				master_password         = "bar"
		 				backup_retention_period = 5
		 				preferred_backup_window = "07:00-09:00"
		 			}
		 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "db instance with retention greater than default passes check",
			source: `
		 	        resource "aws_db_instance" "good_example" {
		 				allocated_storage       = 10
		 				engine                  = "mysql"
		 				engine_version          = "5.7"
		 				instance_class          = "db.t3.micro"
		 				name                    = "mydb"
		 				username                = "foo"
		 				password                = "foobarbaz"
		 				parameter_group_name    = "default.mysql5.7"
		 				backup_retention_period = 5
		 				skip_final_snapshot     = true
		 			}
		 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "db instance with which is a replica with no retention period set passes check",
			source: `
		 			resource "aws_db_instance" "good_example" {
		 				allocated_storage       = 10
		 				engine                  = "mysql"
		 				engine_version          = "5.7"
		 				instance_class          = "db.t3.micro"
		 				name                    = "mydb"
		 				username                = "foo"
		 				password                = "foobarbaz"
		 				parameter_group_name    = "default.mysql5.7"
		 				backup_retention_period = 5
		 				skip_final_snapshot     = true
		 			}

		 	        resource "aws_db_instance" "good_example_replica" {
		 				allocated_storage       = 10
		 				engine                  = "mysql"
		 				engine_version          = "5.7"
		 				instance_class          = "db.t3.micro"
		 				name                    = "mydb"
		 				username                = "foo"
		 				password                = "foobarbaz"
		 				parameter_group_name    = "default.mysql5.7"
		 				replicate_source_db     = aws_db_instance.good_example_replica.arn
		 				skip_final_snapshot     = true
		 			}
		 `,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
