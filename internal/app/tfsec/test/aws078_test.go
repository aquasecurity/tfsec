package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEcrImagesHaveImmutableTags(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "should fire when image_tab_mutability attribute missing",
			source: `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`,
			mustIncludeResultCode: checks.AWSEcrImagesHaveImmutableTags,
		},
		{
			name: "should fire when image_tab_mutability not set to IMMUTABLE",
			source: `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`,
			mustIncludeResultCode: checks.AWSEcrImagesHaveImmutableTags,
		},
		{
			name: "should not fire when image_tab_mutability set to IMMUTABLE",
			source: `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`,
			mustExcludeResultCode: checks.AWSEcrImagesHaveImmutableTags,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
