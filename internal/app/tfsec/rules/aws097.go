package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys = "AWS097"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysDescription = "IAM customer managed policies should not allow decryption actions on all KMS keys"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysImpact = "Identities may be able to decrypt data which they should not have access to"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysResolution = "Scope down the resources of the IAM policy to specific keys"
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysExplanation = `
IAM policies define which actions an identity (user, group, or role) can perform on which resources. Following security best practices, AWS recommends that you allow least privilege. In other words, you should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task.
`
const AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeysBadExample = `
resource "aws_iam_role_policy" "test_policy" {
	name = "test_policy"
	role = aws_iam_role.test_role.id

	policy = data.aws_iam_policy_document.kms_policy.json
}

resource "aws_iam_role" "test_role" {
	name = "test_role"
	assume_role_policy = jsonencode({
		Version = "2012-10-17"
		Statement = [
		{
			Action = "sts:AssumeRole"
			Effect = "Allow"
			Sid    = ""
			Principal = {
			Service = "ec2.amazonaws.com"
			}
		},
		]
	})
}

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
resource "aws_iam_role_policy" "test_policy" {
	name = "test_policy"
	role = aws_iam_role.test_role.id
  
	policy = data.aws_iam_policy_document.kms_policy.json
}

resource "aws_iam_role" "test_role" {
	name = "test_role"
	assume_role_policy = jsonencode({
		Version = "2012-10-17"
		Statement = [
		{
			Action = "sts:AssumeRole"
			Effect = "Allow"
			Sid    = ""
			Principal = {
			Service = "ec2.amazonaws.com"
			}
		},
		]
	})
}

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

type awsIAMPolicyDocument struct {
	Statements []awsIAMPolicyDocumentStatement `json:"Statement"`
}

type awsIAMPolicyDocumentStatement struct {
	Effect    string                    `json:"Effect"`
	Action    awsIAMPolicyDocumentValue `json:"Action"`
	Resource  awsIAMPolicyDocumentValue `json:"Resource,omitempty"`
	Principal awsIAMPolicyPrincipal     `json:"Principal,omitempty"`
}

type awsIAMPolicyPrincipal struct {
	AWS awsIAMPolicyDocumentValue `json:"AWS"`
}

// AWS allows string or []string as value, we convert everything to []string to avoid casting
type awsIAMPolicyDocumentValue []string

func (value *awsIAMPolicyDocumentValue) UnmarshalJSON(b []byte) error {

	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	var p []string
	//  value can be string or []string, convert everything to []string
	switch v := raw.(type) {
	case string:
		p = []string{v}
	case []interface{}:
		var items []string
		for _, item := range v {
			items = append(items, fmt.Sprintf("%v", item))
		}
		p = items
	default:
		return fmt.Errorf("invalid %s value element: allowed is only string or []string", value)
	}

	*value = p
	return nil
}

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
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_policy", "aws_iam_group_policy", "aws_iam_user_policy", "aws_iam_role_policy"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, ctx *hclcontext.Context) {

			policyAttr := resourceBlock.GetAttribute("policy")
			if policyAttr == nil {
				return
			}

			if policyAttr.IsString() {
				checkAWS097PolicyJSON(set, resourceBlock, policyAttr)
				return
			}

			policyDocumentBlock, err := ctx.GetReferencedBlock(policyAttr)
			if err != nil {
				return
			}

			if policyDocumentBlock.Type() != "data" || policyDocumentBlock.TypeLabel() != "aws_iam_policy_document" {
				return
			}

			if statementBlocks := policyDocumentBlock.GetBlocks("statement"); statementBlocks != nil {
				for _, statementBlock := range statementBlocks {

					// Denying a broad set of KMS access is fine
					if statementBlock.HasChild("effect") && statementBlock.GetAttribute("effect").Equals("deny", block.IgnoreCase) {
						continue
					}

					if statementBlock.HasChild("actions") && statementBlock.GetAttribute("actions").Contains("kms") {
						if resources := statementBlock.GetAttribute("resources"); resources != nil {
							if resources.Contains("*") {
								set.Add(
									result.New(policyDocumentBlock).
										WithDescription(fmt.Sprintf("Resource '%s' a policy with KMS actions for all KMS keys.", policyDocumentBlock.FullName())).
										WithRange(resources.Range()).
										WithAttributeAnnotation(resources),
								)
							}
						}
					}
				}
			}
		},
	})
}

func checkAWS097PolicyJSON(set result.Set, resourceBlock block.Block, policyAttr block.Attribute) {
	var document awsIAMPolicyDocument
	if err := json.Unmarshal([]byte(policyAttr.Value().AsString()), &document); err != nil {
		return
	}
	for _, statement := range document.Statements {
		if strings.ToLower(statement.Effect) == "deny" {
			continue
		}
		for _, action := range statement.Action {
			if !strings.HasPrefix(action, "kms:") {
				continue
			}
			for _, resource := range statement.Resource {
				if strings.Contains(resource, "*") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' a policy with KMS actions for all KMS keys.", resourceBlock.FullName())).
							WithRange(policyAttr.Range()).
							WithAttributeAnnotation(policyAttr),
					)
					return
				}
			}
		}
	}
}
