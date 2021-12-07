package dynamodb
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSDAXEncryptedAtRest(t *testing.T) {
// 	expectedCode := "aws-dynamodb-enable-at-rest-encryption"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "Rule should not pass when no SSE block at all",
// 			source: `
// resource "aws_dax_cluster" "bad_example" {
// 	// no server side encryption at all
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		}, {
// 			name: "Rule should not pass when SSE block empty",
// 			source: `
// resource "aws_dax_cluster" "bad_example" {
// 	// other DAX config
// 
// 	server_side_encryption {
// 		// empty server side encryption config
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule should not pass when SSE disabled",
// 			source: `
// resource "aws_dax_cluster" "bad_example" {
// 	// other DAX config
// 
// 	server_side_encryption {
// 		enabled = false // disabled server side encryption
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule should pass when SSE is enabled",
// 			source: `
// resource "aws_dax_cluster" "good_example" {
// 	// other DAX config
// 
// 	server_side_encryption {
// 		enabled = true // enabled server side encryption
// 	}
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
