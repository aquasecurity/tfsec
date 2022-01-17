package rds

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSRDSPerformanceInsughtsEncryptionNotEnabled(t *testing.T) {
	expectedCode := "aws-rds-enable-performance-insights"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Performance insights enabled but no kms key provided",
			source: `
resource "aws_rds_cluster" "cluster1" {

}

 resource "aws_rds_cluster_instance" "foo" {
   name                            = "bar"
   performance_insights_enabled    = true
   performance_insights_kms_key_id = ""
   cluster_identifier              = aws_rds_cluster.cluster1.id
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Performance insights disable",
			source: `
resource "aws_rds_cluster" "cluster1" {

}

 resource "aws_rds_cluster_instance" "foo" {
   name                         = "bar"
   performance_insights_enabled = false
   cluster_identifier           = aws_rds_cluster.cluster1.id
 
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Performance insights not mentioned",
			source: `
resource "aws_rds_cluster" "cluster1" {

}

 resource "aws_rds_cluster_instance" "foo" {
	cluster_identifier   = aws_rds_cluster.cluster1.id
   
   
}
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Performance insights enabled and kms key provided",
			source: `
resource "aws_rds_cluster" "cluster1" {

}

 resource "aws_rds_cluster_instance" "foo" {
   cluster_identifier   = aws_rds_cluster.cluster1.id
   name                 = "bar"
   performance_insights_enabled = true
   performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Performance insights on aws_db_instance enabled but no kms key provided",
			source: `
 resource "aws_db_instance" "foo" {
   name                 = "bar"
   performance_insights_enabled = true
   performance_insights_kms_key_id = ""
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Performance insights on aws_db_instance disable",
			source: `
 resource "aws_db_instance" "foo" {
   name                 = "bar"
   performance_insights_enabled = false
 
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Performance insights on aws_db_instance not mentioned",
			source: `
 resource "aws_db_instance" "foo" {
   
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Performance insights enabled on aws_db_instance and kms key provided",
			source: `
 resource "aws_db_instance" "foo" {
   name                 = "bar"
   performance_insights_enabled = true
   performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Testing issue 506: error when performance insights enabled and kms included",
			source: `
resource "aws_rds_cluster" "cluster1" {

}

 resource "aws_rds_cluster_instance" "covidshield_server_instances" {
   count                        = 3
 
   identifier           = "${var.rds_server_db_name}-instance-${count.index}"
   cluster_identifier   = aws_rds_cluster.cluster1.id
   instance_class       = var.rds_server_instance_class
   db_subnet_group_name = aws_db_subnet_group.covidshield.name
 
   # we are using managed key so safe to ignore this rule
   performance_insights_enabled = true 
   performance_insights_kms_key_id = "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:alias/aws/rds"
   tags = {
     Name                  = "${var.rds_server_db_name}-instance"
     (var.billing_tag_key) = var.billing_tag_value
   }
 }`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Testing issue 505",
			source: `
 resource "aws_kms_key" "rds_storage" {
   description             = "KMS key 1"
   deletion_window_in_days = 10
 }
 
 locals {
 	performance_insights_supported = true
 }
 
 resource "aws_rds_cluster_instance" "this" {
    apply_immediately               = (var.environment != "production")
    for_each                        = aws_rds_cluster.this.availability_zones
    cluster_identifier              = aws_rds_cluster.this.id
    identifier_prefix               = lower(var.deployment_id)
    publicly_accessible             = false
    availability_zone               = each.key
    engine                          = "aurora-mysql"
    tags                            = var.tags
    instance_class                  = var.database_instance_class
    db_subnet_group_name            = aws_db_subnet_group.this.name
    copy_tags_to_snapshot           = true
    performance_insights_enabled    = local.performance_insights_supported
    performance_insights_kms_key_id = local.performance_insights_supported ? aws_kms_key.rds_storage.arn : null
  }`,
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
