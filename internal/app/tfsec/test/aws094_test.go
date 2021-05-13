package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSRedshiftAtRestEncryption(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "redshift cluster without encryption fails check",
			source: `
resource "aws_redshift_cluster" "bad_example" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
}
`,
			mustIncludeResultCode: checks.AWSRedshiftAtRestEncryption,
		},
		{
			name: "redshift cluster with encryption disabled fails check",
			source: `
resource "aws_redshift_cluster" "bad_example" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = false
}
`,
			mustIncludeResultCode: checks.AWSRedshiftAtRestEncryption,
		},
		{
			name: "redshift cluster with encryption enabled but no CMK specified fails check",
			source: `
resource "aws_redshift_cluster" "bad_example" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = true
}
`,
			mustIncludeResultCode: checks.AWSRedshiftAtRestEncryption,
		},
		{
			name: "redshift cluster with encryption enabled and CMK specified passes check",
			source: `
resource "aws_kms_key" "redshift" {
	enable_key_rotation = true
}

resource "aws_redshift_cluster" "good_example" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = true
  kms_key_id         = aws_kms_key.redshift.key_id
}
`,
			mustExcludeResultCode: checks.AWSRedshiftAtRestEncryption,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
