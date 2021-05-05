package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSDontUseDefaultVPC(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Default aws vpc is present so check fails",
			source: `
resource "aws_default_vpc" "default" {
	tags = {
	  Name = "Default VPC"
	}
  }
`,
			mustIncludeResultCode: checks.AWSDontUseDefaultAWSVPC,
		},
		{
			name: "Default aws vpc is not present so check passes",
			source: `
`,
			mustExcludeResultCode: checks.AWSDontUseDefaultAWSVPC,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
