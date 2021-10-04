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
		LegacyID:  "AWS023",
		Service:   "ecr",
		ShortCode: "enable-image-scans",
		Documentation: rule.RuleDocumentation{
			Summary:    "ECR repository has image scans disabled.",
			Impact:     "The ability to scan images is not being used and vulnerabilities will not be highlighted",
			Resolution: "Enable ECR image scanning",
			Explanation: `
Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.
`,
			BadExample: []string{`
resource "aws_ecr_repository" "bad_example" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}
`},
			GoodExample: []string{`
resource "aws_ecr_repository" "good_example" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#image_scanning_configuration",
				"https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecr_repository"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			if resourceBlock.MissingChild("image_scanning_configuration") {
				set.AddResult().
					WithDescription("Resource '%s' defines a disabled ECR image scan.", resourceBlock.FullName())
				return
			}

			ecrScanStatusAttr := resourceBlock.GetNestedAttribute("image_scanning_configuration.scan_on_push")

			if ecrScanStatusAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines a disabled ECR image scan.", resourceBlock.FullName())
			} else if ecrScanStatusAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines a disabled ECR image scan.", resourceBlock.FullName()).
					WithAttribute(ecrScanStatusAttr)
			}
		},
	})
}
