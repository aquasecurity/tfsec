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
		LegacyID:  "AWS093",
		Service:   "ecr",
		ShortCode: "repository-customer-key",
		Documentation: rule.RuleDocumentation{
			Summary: "ECR Repository should use customer managed keys to allow more control",
			Explanation: `
Images in the ECR repository are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.

`,
			Impact:     "Using AWS managed keys does not allow for fine grained control",
			Resolution: "Use customer managed keys",
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
		kms_key = aws_kms_key.ecr_kms.arn
	}
  }
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration",
				"https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecr_repository"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("encryption_configuration") {
				set.AddResult().
					WithDescription("Resource '%s' does not have CMK encryption configured", resourceBlock.FullName())
				return
			}

			encBlock := resourceBlock.GetBlock("encryption_configuration")
			if encBlock.MissingChild("kms_key") {
				set.AddResult().
					WithDescription("Resource '%s' configures encryption without using CMK", resourceBlock.FullName()).
					WithBlock(encBlock)
				return
			}

			if encBlock.MissingChild("encryption_type") || encBlock.GetAttribute("encryption_type").Equals("AES256") {
				set.AddResult().
					WithDescription("Resource '%s' should have the encryption type set to KMS", resourceBlock.FullName()).
					WithBlock(encBlock)
			}

		},
	})
}
