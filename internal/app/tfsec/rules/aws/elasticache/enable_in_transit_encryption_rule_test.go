package elasticache
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSUnencryptedInTransitElasticacheReplicationGroup(t *testing.T) {
// 	expectedCode := "aws-elasticache-enable-in-transit-encryption"
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check aws_elasticache_replication_group missing transit_encryption_enabled",
// 			source: `
// resource "aws_elasticache_replication_group" "my-resource" {
//         replication_group_id = "foo"
//         replication_group_description = "my foo cluster"
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_elasticache_replication_group with transit_encryption_enabled",
// 			source: `
// resource "aws_elasticache_replication_group" "my-resource" {
//         replication_group_id = "foo"
//         replication_group_description = "my foo cluster"
// 
//         transit_encryption_enabled = true
// }`,
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
