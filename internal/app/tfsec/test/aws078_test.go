package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSEcrImagesHaveImmutableTags(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
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
			mustIncludeResultCode: rules.AWSEcrImagesHaveImmutableTags,
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
			mustIncludeResultCode: rules.AWSEcrImagesHaveImmutableTags,
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
			mustExcludeResultCode: rules.AWSEcrImagesHaveImmutableTags,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
