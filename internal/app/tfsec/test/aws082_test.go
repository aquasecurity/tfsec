package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSDontUseDefaultVPC(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
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
			mustIncludeResultCode: rules.AWSDontUseDefaultAWSVPC,
		},
		{
			name: "Default aws vpc is not present so check passes",
			source: `
`,
			mustExcludeResultCode: rules.AWSDontUseDefaultAWSVPC,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
