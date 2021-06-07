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

const AWSECRRepoCustomerManagedKeys = "AWS093"
const AWSECRRepoCustomerManagedKeysDescription = "ECR Repository should use customer managed keys to allow more control"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSECRRepoCustomerManagedKeys,
		Documentation: rule.RuleDocumentation{
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
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if block.MissingChild("encryption_configuration") {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' does not have CMK encryption configured", block.FullName())).
						WithRange(block.Range()).
						WithSeverity(severity.Info),
				)
			}

			encBlock := block.GetBlock("encryption_configuration")
			if encBlock.MissingChild("kms_key") {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' configures encryption without using CMK", block.FullName())).
WithRange(encBlock.Range()).
						WithSeverity(severity.Info),
				)
			}

			if encBlock.MissingChild("encryption_type") || encBlock.GetAttribute("encryption_type").Equals("AES256") {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' should have the encryption type set to KMS", block.FullName())).
WithRange(encBlock.Range()).
						WithSeverity(severity.Info),
				)
			}

		},
	})
}
