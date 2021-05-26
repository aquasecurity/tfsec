package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSECRRepoCustomerManagedKeys scanner.RuleCode = "AWS093"
const AWSECRRepoCustomerManagedKeysDescription scanner.RuleSummary = "ECR Repository should use customer managed keys to allow more control"
const AWSECRRepoCustomerManagedKeysImpact = "Using AWS managed keys does not allow for fine grained control"
const AWSECRRepoCustomerManagedKeysResolution = "Use customer managed keys"
const AWSECRRepoCustomerManagedKeysExplanation = `
Images in the ECR repository are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.

`
const AWSECRRepoCustomerManagedKeysBadExample = `
resource "aws_ecr_repository" "bad_example" {
	name                 = "bar"
	image_tag_mutability = "MUTABLE"
  
	image_scanning_configuration {
	  scan_on_push = true
	}
  }
`
const AWSECRRepoCustomerManagedKeysGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSECRRepoCustomerManagedKeys,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSECRRepoCustomerManagedKeysDescription,
			Explanation: AWSECRRepoCustomerManagedKeysExplanation,
			Impact:      AWSECRRepoCustomerManagedKeysImpact,
			Resolution:  AWSECRRepoCustomerManagedKeysResolution,
			BadExample:  AWSECRRepoCustomerManagedKeysBadExample,
			GoodExample: AWSECRRepoCustomerManagedKeysGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration",
				"https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("encryption_configuration") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have CMK encryption configured", block.FullName()),
						block.Range(),
						scanner.SeverityInfo,
					),
				}
			}

			encBlock := block.GetBlock("encryption_configuration")
			if encBlock.MissingChild("kms_key") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' configures encryption without using CMK", block.FullName()),
						encBlock.Range(),
						scanner.SeverityInfo,
					),
				}
			}

			if encBlock.MissingChild("encryption_type") || encBlock.GetAttribute("encryption_type").Equals("AES256") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have the encryption type set to KMS", block.FullName()),
						encBlock.Range(),
						scanner.SeverityInfo,
					),
				}
			}

			return nil
		},
	})
}
