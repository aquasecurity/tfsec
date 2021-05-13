package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSDynamoDBTableEncryption(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "DynamoDB table using default encryption fails check",
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
  }
`,
			mustIncludeResultCode: checks.AWSDynamoDBTableEncryption,
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
			mustIncludeResultCode: checks.AWSDynamoDBTableEncryption,
		},
		{
			name: "DynamoDB Table with enabled server side encryption using default key fails check",
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
		enabled     = true
		kms_key_arn = "alias/aws/dynamodb"
	}
  }
`,
			mustIncludeResultCode: checks.AWSDynamoDBTableEncryption,
		},
		{
			name: "DynamoDB table that uses KMS CMK passes check",
			source: `
resource "aws_kms_key" "dynamo_db_kms" {
	enable_key_rotation = true
}

resource "aws_dynamodb_table" "good_example" {
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
		enabled     = true
		kms_key_arn = aws_kms_key.dynamo_db_kms.key_id
	}
  }
`,
			mustExcludeResultCode: checks.AWSDynamoDBTableEncryption,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
