package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEcrImagesHaveImmutableTags = "AWS078"
const AWSEcrImagesHaveImmutableTagsDescription = "ECR images tags shouldn't be mutable."
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSEcrImagesHaveImmutableTags,
		Documentation: rule.RuleDocumentation{
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
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			imageTagMutability := block.GetAttribute("image_tag_mutability")
			if imageTagMutability == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' is missing `image_tag_mutability` attribute - it is required to make ecr image tag immutable.", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			if !imageTagMutability.Equals("IMMUTABLE") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' has `image_tag_mutability` attribute  not set to `IMMUTABLE`", block.FullName()),
						imageTagMutability.Range(),
						severity.Error,
					),
				}
			}

			return nil
		},
	})
}
