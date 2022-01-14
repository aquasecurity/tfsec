package dynamodb

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSDAXEncryptedAtRest(t *testing.T) {
	expectedCode := "aws-dynamodb-enable-at-rest-encryption"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule should not pass when no SSE block at all",
			source: `
 resource "aws_dax_cluster" "bad_example" {
 	// no server side encryption at all
 }
 `,
			mustIncludeResultCode: expectedCode,
		}, {
			name: "Rule should not pass when SSE block empty",
			source: `
 resource "aws_dax_cluster" "bad_example" {
 	// other DAX config
 
 	server_side_encryption {
 		// empty server side encryption config
 	}
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule should not pass when SSE disabled",
			source: `
 resource "aws_dax_cluster" "bad_example" {
 	// other DAX config
 
 	server_side_encryption {
 		enabled = false // disabled server side encryption
 	}
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule should pass when SSE is enabled",
			source: `
 resource "aws_dax_cluster" "good_example" {
 	// other DAX config
 
 	server_side_encryption {
 		enabled = true // enabled server side encryption
 	}
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "DynamoDB Table with disabled server side encryption fails check",
			source: `
 resource "aws_dynamodb_table" "bad_example" {
 	name             = "example"
 	hash_key         = "TestTableHashKey"
 	billing_mode     = "PAY_PER_REQUEST"
 	stream_enabled   = true
 	stream_view_type = "NEW_AND_OLD_IMAGES"
   
 	attribute {
 	  name = "TestTableHashKey"
 	  type = "S"
 	}
   
 	replica {
 	  region_name = "us-east-2"
 	}
   
 	replica {
 	  region_name = "us-west-2"
 	}
 
 	server_side_encryption {
 		enabled     = false
 		kms_key_arn = aws_kms_key.dynamo_db_kms
 	}
   }
 `,
			mustIncludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
