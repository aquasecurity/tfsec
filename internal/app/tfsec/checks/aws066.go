package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEKSSecretsEncryptionEnabled scanner.RuleCode = "AWS066"
const AWSEKSSecretsEncryptionEnabledDescription scanner.RuleSummary = "EKS should have the encryption of secrets enabled"
const AWSEKSSecretsEncryptionEnabledExplanation = `
EKS cluster resources should have the encryption_config block set with protection of the secrets resource.
`
const AWSEKSSecretsEncryptionEnabledBadExample = `
resource "aws_eks_cluster" "bad_example" {
    name = "bad_example_cluster"

    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`
const AWSEKSSecretsEncryptionEnabledGoodExample = `
resource "aws_eks_cluster" "good_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEKSSecretsEncryptionEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEKSSecretsEncryptionEnabledDescription,
			Explanation: AWSEKSSecretsEncryptionEnabledExplanation,
			BadExample:  AWSEKSSecretsEncryptionEnabledBadExample,
			GoodExample: AWSEKSSecretsEncryptionEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config",
				"https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
				
			if block.MissingChild("encryption_config") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has no encryption_config block", block.FullName()),
						block.Range(),
						scanner.SeverityError,
						),
				}
			}

			encryption_config := block.GetBlock("encryption_config")
			if encryption_config.MissingChild("resources") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has encryption_config block with no resources attribute specified", block.FullName()),
						encryption_config.Range(),
						scanner.SeverityError,
					),
				}
			}

			resources := encryption_config.GetAttribute("resources")
			if !resources.Contains("secrets") {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' does not include secrets in encrypted resources", block.FullName()),
						resources.Range(),
						resources,
						scanner.SeverityError,
					),
				}
			}

			if encryption_config.MissingChild("provider") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has encryption_config block with no provider block specified", block.FullName()),
						encryption_config.Range(),
						scanner.SeverityError,
					),
				}
			}

			providerBlock := encryption_config.GetBlock("provider")
			if providerBlock.MissingChild("key_arn"){
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has encryption_config block with provider block specified missing key arn", block.FullName()),
						encryption_config.Range(),
						scanner.SeverityError,
					),
				}
			}

			keyArn := providerBlock.GetAttribute("key_arn")
			if keyArn.IsEmpty() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has encryption_config block with provider block specified but key_arn is empty", block.FullName()),
						keyArn.Range(),
						keyArn,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
