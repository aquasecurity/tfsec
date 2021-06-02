package rules

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSSecretsManagerSecretEncryption = "AWS095"
const AWSSecretsManagerSecretEncryptionDescription = "Secrets Manager should use customer managed keys"
const AWSSecretsManagerSecretEncryptionImpact = "Using AWS managed keys reduces the flexibility and control over the encryption key"
const AWSSecretsManagerSecretEncryptionResolution = "Use customer managed keys"
const AWSSecretsManagerSecretEncryptionExplanation = `
Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explictly.
`
const AWSSecretsManagerSecretEncryptionBadExample = `
resource "aws_secretsmanager_secret" "bad_example" {
  name       = "lambda_password"
}
`
const AWSSecretsManagerSecretEncryptionGoodExample = `
resource "aws_kms_key" "secrets" {
	enable_key_rotation = true
}

resource "aws_secretsmanager_secret" "good_example" {
  name       = "lambda_password"
  kms_key_id = aws_kms_key.secrets.arn
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSSecretsManagerSecretEncryption,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSSecretsManagerSecretEncryptionDescription,
			Explanation: AWSSecretsManagerSecretEncryptionExplanation,
			Impact:      AWSSecretsManagerSecretEncryptionImpact,
			Resolution:  AWSSecretsManagerSecretEncryptionResolution,
			BadExample:  AWSSecretsManagerSecretEncryptionBadExample,
			GoodExample: AWSSecretsManagerSecretEncryptionGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id",
				"https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_secretsmanager_secret"},
		CheckFunc: func(block *block.Block, ctx *hclcontext.Context) []result.Result {

			if block.MissingChild("kms_key_id") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' does not use CMK", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Info,
					),
				}
			}

			kmsKeyAttr := block.GetAttribute("kms_key_id")
			if kmsKeyAttr.ReferencesDataBlock() {
				ref := kmsKeyAttr.ReferenceAsString()
				dataReferenceParts := strings.Split(ref, ".")
				if len(dataReferenceParts) < 3 {
					return nil
				}
				blockType := dataReferenceParts[0]
				blockName := dataReferenceParts[1]
				kmsKeyDatas := ctx.GetDatasByType(blockType)
				for _, kmsData := range kmsKeyDatas {
					if kmsData.NameLabel() == blockName {
						keyIdAttr := kmsData.GetAttribute("key_id")
						if keyIdAttr != nil && keyIdAttr.Equals("alias/aws/secretsmanager") {
							set.Add(
								result.New().WithDescription(
									fmt.Sprintf("Resource '%s' explicitly uses the default CMK", block.FullName()),
									kmsKeyAttr.Range(),
									kmsKeyAttr,
									severity.Info,
								),
							}
						}
					}

				}
			}

			return nil
		},
	})
}
