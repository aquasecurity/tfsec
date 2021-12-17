package ecr

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS023",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		Base:           ecr.CheckEnableImageScans,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("image_scanning_configuration") {
				results.Add("Resource defines a disabled ECR image scan.", resourceBlock)
				return
			}

			ecrScanStatusAttr := resourceBlock.GetNestedAttribute("image_scanning_configuration.scan_on_push")
			if ecrScanStatusAttr.IsNil() {
				results.Add("Resource defines a disabled ECR image scan.", resourceBlock)
			} else if ecrScanStatusAttr.IsFalse() {
				results.Add("Resource defines a disabled ECR image scan.", ecrScanStatusAttr)
			}

			return results
		},
	})
}
