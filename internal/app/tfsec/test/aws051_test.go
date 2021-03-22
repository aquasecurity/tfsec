package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSRDSAuroraClusterEncryptionDisabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check rds is not specified",
			source: `
resource "aws_rds_cluster" "my-instance" {
	name = "cluster-1"
}
`,
			mustIncludeResultCode: checks.AWSRDSAuroraClusterEncryptionDisabled,
		},
		{
			name: "check rds kms is specified but false",
			source: `
resource "aws_rds_cluster" "my-instance" {
	name       = "cluster-1"
	kms_key_id  = ""
}
`,
			mustIncludeResultCode: checks.AWSRDSAuroraClusterEncryptionDisabled,
		},
		{
			name: "check rds kms is specified but not storage_encrypted",
			source: `
resource "aws_rds_cluster" "my-instance" {
	name       = "cluster-1"
	kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
`,
			mustIncludeResultCode: checks.AWSRDSAuroraClusterEncryptionDisabled,
		},
		{
			name: "check rds storage_encrypted is false and key_id is null",
			source: `
resource "aws_rds_cluster" "my-instance" {
	name       = "cluster-1"
	storage_encrypted = false
	kms_key_id = null
}
`,
			mustIncludeResultCode: checks.AWSRDSAuroraClusterEncryptionDisabled,
		},
		{
			name: "check rds encryption is enabled correctly",
			source: `
resource "aws_rds_cluster" "my-instance" {
	name              = "cluster-1"
	kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	storage_encrypted = true
}
`,
			mustExcludeResultCode: checks.AWSRDSAuroraClusterEncryptionDisabled,
		},
		{
			name: "verify issue 633 ",
			source: `
resource "aws_kms_key" "rds" {
enable_key_rotation = true
}

resource "aws_rds_cluster" "rds_cluster" {
engine                          = "aurora-mysql"
engine_version                  = "5.7.mysql_aurora.2.09.1"
storage_encrypted               = true
kms_key_id                      = aws_kms_key.rds.arn
}
`,
			mustExcludeResultCode: checks.AWSRDSAuroraClusterEncryptionDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}


