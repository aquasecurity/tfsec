package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEcrImagesHaveImmutableTags scanner.RuleCode = "AWS078"
const AWSEcrImagesHaveImmutableTagsDescription scanner.RuleSummary = "ECR images tags shouldn't be mutable."
const AWSEcrImagesHaveImmutableTagsImpact = "Image tags could be overwritten with compromised images"
const AWSEcrImagesHaveImmutableTagsResolution = "Only use immutable images in ECR"
const AWSEcrImagesHaveImmutableTagsExplanation = `
ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>
`
const AWSEcrImagesHaveImmutableTagsBadExample = `
resource "aws_ecr_repository" "bad_example" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`
const AWSEcrImagesHaveImmutableTagsGoodExample = `
resource "aws_ecr_repository" "good_example" {
  name                 = "bar"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEcrImagesHaveImmutableTags,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEcrImagesHaveImmutableTagsDescription,
			Impact:      AWSEcrImagesHaveImmutableTagsImpact,
			Resolution:  AWSEcrImagesHaveImmutableTagsResolution,
			Explanation: AWSEcrImagesHaveImmutableTagsExplanation,
			BadExample:  AWSEcrImagesHaveImmutableTagsBadExample,
			GoodExample: AWSEcrImagesHaveImmutableTagsGoodExample,
			Links: []string{
				"https://sysdig.com/blog/toctou-tag-mutability/",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			imageTagMutability := block.GetAttribute("image_tag_mutability")
			if imageTagMutability == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is missing `image_tag_mutability` attribute - it is required to make ecr image tag immutable.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if !imageTagMutability.Equals("IMMUTABLE") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has `image_tag_mutability` attribute  not set to `IMMUTABLE`", block.FullName()),
						imageTagMutability.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
