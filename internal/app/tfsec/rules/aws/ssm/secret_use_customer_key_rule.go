package ssm

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
		LegacyID:  "AWS095",
		Service:   "ssm",
		ShortCode: "secret-use-customer-key",
		Documentation: rule.RuleDocumentation{
			Summary: "Secrets Manager should use customer managed keys",
			Explanation: `
Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.
`,
			Impact:     "Using AWS managed keys reduces the flexibility and control over the encryption key",
			Resolution: "Use customer managed keys",
			BadExample: []string{`
resource "aws_secretsmanager_secret" "bad_example" {
  name       = "lambda_password"
}
`},
			GoodExample: []string{`
resource "aws_kms_key" "secrets" {
	enable_key_rotation = true
}

resource "aws_secretsmanager_secret" "good_example" {
  name       = "lambda_password"
  kms_key_id = aws_kms_key.secrets.arn
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id",
				"https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_secretsmanager_secret"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			if resourceBlock.MissingChild("kms_key_id") {
				set.AddResult().
					WithDescription("Resource '%s' does not use CMK", resourceBlock.FullName())
				return
			}

			kmsKeyAttr := resourceBlock.GetAttribute("kms_key_id")
			if kmsKeyAttr.IsDataBlockReference() {
				kmsData, err := module.GetReferencedBlock(kmsKeyAttr)
				if err != nil {
					return
				}
				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr.IsNotNil() && keyIdAttr.Equals("alias/aws/secretsmanager") {
					set.AddResult().
						WithDescription("Resource '%s' explicitly uses the default CMK", resourceBlock.FullName()).
						WithAttribute(kmsKeyAttr)
				}
			}

		},
	})
}
