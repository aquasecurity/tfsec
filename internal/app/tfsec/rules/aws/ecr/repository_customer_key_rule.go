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
		LegacyID: "AWS093",
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
 resource "aws_kms_key" "ecr_kms" {
 	enable_key_rotation = true
 }
 
 resource "aws_ecr_repository" "good_example" {
 	name                 = "bar"
 	image_tag_mutability = "MUTABLE"
   
 	image_scanning_configuration {
 	  scan_on_push = true
 	}
 
 	encryption_configuration {
 		encryption_type = "KMS"
 		kms_key = aws_kms_key.ecr_kms.key_id
 	}
   }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration",
			"https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		Base:           ecr.CheckRepositoryCustomerKey,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("encryption_configuration") {
				results.Add("Resource does not have CMK encryption configured", resourceBlock)
				return
			}

			encBlock := resourceBlock.GetBlock("encryption_configuration")
			if encBlock.MissingChild("kms_key") {
				results.Add("Resource configures encryption without using CMK", encBlock)
				return
			}

			if encBlock.MissingChild("encryption_type") || encBlock.GetAttribute("encryption_type").Equals("AES256") {
				results.Add("Resource should have the encryption type set to KMS", encBlock)
			}

			return results
		},
	})
}
