package ecr

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSEcrImageScanNotEnabled(t *testing.T) {
	expectedCode := "aws-ecr-enable-image-scans"
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check ECR Image Scan disabled",
			source:                `resource "aws_ecr_repository" "foo" {}`,
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check ECR Image Scan on push not set",
			source: `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
  }
}`,
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
