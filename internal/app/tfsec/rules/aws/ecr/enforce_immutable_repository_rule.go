package ecr

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS078",
		Service:   "ecr",
		ShortCode: "enforce-immutable-repository",
		Documentation: rule.RuleDocumentation{
			Summary:    "ECR images tags shouldn't be mutable.",
			Impact:     "Image tags could be overwritten with compromised images",
			Resolution: "Only use immutable images in ECR",
			Explanation: `
ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>
`,
			BadExample: []string{`
resource "aws_ecr_repository" "bad_example" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`},
			GoodExample: []string{`
resource "aws_ecr_repository" "good_example" {
  name                 = "bar"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository",
				"https://sysdig.com/blog/toctou-tag-mutability/",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecr_repository"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			imageTagMutabilityAttr := resourceBlock.GetAttribute("image_tag_mutability")
			if imageTagMutabilityAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' is missing `image_tag_mutability` attribute - it is required to make ecr image tag immutable.", resourceBlock.FullName())
				return
			}

			if imageTagMutabilityAttr.NotEqual("IMMUTABLE") {
				set.AddResult().
					WithDescription("Resource '%s' has `image_tag_mutability` attribute  not set to `IMMUTABLE`", resourceBlock.FullName()).
					WithAttribute(imageTagMutabilityAttr)
			}

		},
	})
}
