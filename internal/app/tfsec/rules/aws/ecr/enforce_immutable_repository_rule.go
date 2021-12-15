package ecr

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS078",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		Base:           ecr.CheckEnforceImmutableRepository,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			imageTagMutabilityAttr := resourceBlock.GetAttribute("image_tag_mutability")
			if imageTagMutabilityAttr.IsNil() {
				results.Add("Resource is missing `image_tag_mutability` attribute - it is required to make ecr image tag immutable.", resourceBlock)
				return
			}

			if imageTagMutabilityAttr.NotEqual("IMMUTABLE") {
				results.Add("Resource has `image_tag_mutability` attribute  not set to `IMMUTABLE`", imageTagMutabilityAttr)
			}

			return results
		},
	})
}
