package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/result"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys = "AWS097"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysDescription = "IAM customer managed policies should not allow decryption actions on all KMS keys"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysImpact = "Identities may be able to decrypt data which they should not have access to"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysResolution = "Scope down the resources of the IAM policy to specific keys"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysExplanation = `
IAM policies define which actions an identity (user, group, or role) can perform on which resources. Following security best practices, AWS recommends that you allow least privilege. In other words, you should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task.
`
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysBadExample = `
data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}
`
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysGoodExample = `
data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = [aws_kms_key.main.arn]
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysDescription,
			Explanation: AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysExplanation,
			Impact:      AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysImpact,
			Resolution:  AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysResolution,
			BadExample:  AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysBadExample,
			GoodExample: AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-kms-1",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"data"},
		RequiredLabels:  []string{"aws_iam_policy_document"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if statementBlocks := resourceBlock.GetBlocks("statement"); statementBlocks != nil {
				for _, statementBlock := range statementBlocks {

					// Denying a broad set of KMS access is fine
					if statementBlock.HasChild("effect") && statementBlock.GetAttribute("effect").Equals("deny", block.IgnoreCase) {
						continue
					}

					if statementBlock.HasChild("actions") && statementBlock.GetAttribute("actions").Contains("kms") {
						if resources := statementBlock.GetAttribute("resources"); resources != nil {
							if resources.Contains("*") {
								set.Add(
									result.New(resourceBlock).
										WithDescription(fmt.Sprintf("Resource '%s' a policy with KMS actions for all KMS keys.", resourceBlock.FullName())).
										WithRange(resourceBlock.Range()).
										WithAttributeAnnotation(resources).
										WithSeverity(severity.Error),
								)
							}
						}
					}
				}
			}
		},
	})
}
