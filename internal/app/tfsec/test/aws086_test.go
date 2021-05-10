package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSDynamoDBRecoveryEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "table with no point in time recovery fails check",
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
}
`,
			mustIncludeResultCode: checks.AWSDynamoDBRecoveryEnabled,
		},
		{
			name: "table with point in time recovery set but disabled fails check",
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

	point_in_time_recovery {
		enabled = false
	}
}
`,
			mustIncludeResultCode: checks.AWSDynamoDBRecoveryEnabled,
		},
		{
			name: "table with point in time recovery passes check",
			source: `
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

	point_in_time_recovery {
		enabled = true
	}
}
`,
			mustExcludeResultCode: checks.AWSDynamoDBRecoveryEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
