package redshift
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSRedshiftAtRestEncryption(t *testing.T) {
// 	expectedCode := "aws-redshift-encryption-customer-key"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "redshift cluster without encryption fails check",
// 			source: `
// resource "aws_redshift_cluster" "bad_example" {
//   cluster_identifier = "tf-redshift-cluster"
//   database_name      = "mydb"
//   master_username    = "foo"
//   master_password    = "Mustbe8characters"
//   node_type          = "dc1.large"
//   cluster_type       = "single-node"
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "redshift cluster with encryption disabled fails check",
// 			source: `
// resource "aws_redshift_cluster" "bad_example" {
//   cluster_identifier = "tf-redshift-cluster"
//   database_name      = "mydb"
//   master_username    = "foo"
//   master_password    = "Mustbe8characters"
//   node_type          = "dc1.large"
//   cluster_type       = "single-node"
//   encrypted          = false
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "redshift cluster with encryption enabled but no CMK specified fails check",
// 			source: `
// resource "aws_redshift_cluster" "bad_example" {
//   cluster_identifier = "tf-redshift-cluster"
//   database_name      = "mydb"
//   master_username    = "foo"
//   master_password    = "Mustbe8characters"
//   node_type          = "dc1.large"
//   cluster_type       = "single-node"
//   encrypted          = true
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "redshift cluster with encryption enabled and CMK specified passes check",
// 			source: `
// resource "aws_kms_key" "redshift" {
// 	enable_key_rotation = true
// }
// 
// resource "aws_redshift_cluster" "good_example" {
//   cluster_identifier = "tf-redshift-cluster"
//   database_name      = "mydb"
//   master_username    = "foo"
//   master_password    = "Mustbe8characters"
//   node_type          = "dc1.large"
//   cluster_type       = "single-node"
//   encrypted          = true
//   kms_key_id         = aws_kms_key.redshift.key_id
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }
