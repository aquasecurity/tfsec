package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEcrImageScanNotEnabled(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name:                  "check ECR Image Scan disabled",
			source:                `resource "aws_ecr_repository" "foo" {}`,
			mustIncludeResultCode: checks.AWSEcrImageScanNotEnabled,
		},
		{
			name: "check ECR Image Scan disabled",
			source: `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}`,
			mustIncludeResultCode: checks.AWSEcrImageScanNotEnabled,
		},
		{
			name: "check ECR Image Scan disabled",
			source: `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}`,
			mustExcludeResultCode: checks.AWSEcrImageScanNotEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
