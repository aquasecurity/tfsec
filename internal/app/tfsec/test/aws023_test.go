package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSEcrImageScanNotEnabled(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check ECR Image Scan disabled",
			source:                `resource "aws_ecr_repository" "foo" {}`,
			mustIncludeResultCode: rules.AWSEcrImageScanNotEnabled,
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
			mustIncludeResultCode: rules.AWSEcrImageScanNotEnabled,
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
			mustExcludeResultCode: rules.AWSEcrImageScanNotEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
