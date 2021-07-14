package test

import (
	"testing"
)

func Test_ResourcesWithCount(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "unspecified count defaults to 1",
			source: `
			resource "aws_default_vpc" "this" {}
`,
			mustIncludeResultCode: "AWS082",
		},
		{
			name: "count is 1",
			source: `
			resource "aws_default_vpc" "this" {
				count = 1
			}
`,
			mustIncludeResultCode: "AWS082",
		},
		{
			name: "count is literal 0",
			source: `
			resource "aws_default_vpc" "this" {
				count = 0
			}
`,
			mustExcludeResultCode: "AWS082",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
