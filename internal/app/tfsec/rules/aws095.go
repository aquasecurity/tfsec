package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSSecretsManagerSecretEncryption = "AWS095"
const AWSSecretsManagerSecretEncryptionDescription = "Secrets Manager should use customer managed keys"
const AWSSecretsManagerSecretEncryptionImpact = "Using AWS managed keys reduces the flexibility and control over the encryption key"
const AWSSecretsManagerSecretEncryptionResolution = "Use customer managed keys"
const AWSSecretsManagerSecretEncryptionExplanation = `
Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_secretsmanager_secret"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, ctx *hclcontext.Context) {

			if resourceBlock.MissingChild("kms_key_id") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not use CMK", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			kmsKeyAttr := resourceBlock.GetAttribute("kms_key_id")
			if kmsKeyAttr.IsDataBlockReference() {
				kmsData, err := ctx.GetReferencedBlock(kmsKeyAttr)
				if err != nil {
					return
				}
				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr != nil && keyIdAttr.Equals("alias/aws/secretsmanager") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' explicitly uses the default CMK", resourceBlock.FullName())).
							WithRange(kmsKeyAttr.Range()).
							WithAttributeAnnotation(kmsKeyAttr),
					)
				}
			}

		},
	})
}
