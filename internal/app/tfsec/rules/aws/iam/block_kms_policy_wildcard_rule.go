package iam

// generator-locked
import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/severity"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

type PolicyDocument struct {
	Statements []awsIAMPolicyDocumentStatement `json:"Statement"`
}

type awsIAMPolicyDocumentStatement struct {
	Effect    string                    `json:"Effect"`
	Action    awsIAMPolicyDocumentValue `json:"Action"`
	Resource  awsIAMPolicyDocumentValue `json:"Resource,omitempty"`
	Principal awsIAMPolicyPrincipal     `json:"Principal,omitempty"`
}

type awsIAMPolicyPrincipal struct {
	AWS     []string
	Service []string
}

// AWS allows string or []string as value, we convert everything to []string to avoid casting
type awsIAMPolicyDocumentValue []string

func (value *awsIAMPolicyPrincipal) UnmarshalJSON(b []byte) error {

	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	//  value can be string or []string, convert everything to []string
	switch v := raw.(type) {
	case map[string]interface{}:
		for key, each := range v {
			switch raw := each.(type) {
			case string:
				if key == "Service" {
					value.Service = append(value.Service, raw)
				} else {
					value.AWS = append(value.AWS, raw)
				}
			case []string:
				if key == "Service" {
					value.Service = append(value.Service, raw...)
				} else {
					value.AWS = append(value.AWS, raw...)
				}
			}
		}
	case string:
		value.AWS = []string{v}
	case []interface{}:
		for _, item := range v {
			value.AWS = append(value.AWS, fmt.Sprintf("%v", item))
		}
	default:
		return fmt.Errorf("invalid %s value element: allowed is only string or []string", value)
	}

	return nil
}

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
		LegacyID:  "AWS097",
		Service:   "iam",
		ShortCode: "block-kms-policy-wildcard",
		Documentation: rule.RuleDocumentation{
			Summary: "IAM customer managed policies should not allow decryption actions on all KMS keys",
			Explanation: `
IAM policies define which actions an identity (user, group, or role) can perform on which resources. Following security best practices, AWS recommends that you allow least privilege. In other words, you should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task.
`,
			Impact:     "Identities may be able to decrypt data which they should not have access to",
			Resolution: "Scope down the resources of the IAM policy to specific keys",
			BadExample: []string{`
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

`},
			GoodExample: []string{`
resource "aws_kms_key" "main" {
	enable_key_rotation = true
}

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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document",
				"https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-kms-1",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_policy", "aws_iam_group_policy", "aws_iam_user_policy", "aws_iam_role_policy"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			policyAttr := resourceBlock.GetAttribute("policy")
			if policyAttr.IsNil() {
				return
			}

			if policyAttr.IsString() {
				checkAWS097PolicyJSON(set, resourceBlock, policyAttr)
				return
			}

			policyDocumentBlock, err := module.GetReferencedBlock(policyAttr)
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

					if statementBlock.HasChild("actions") && statementBlock.GetAttribute("actions").HasIntersect("kms:*", "kms:Decrypt") {
						if resources := statementBlock.GetAttribute("resources"); resources.IsNotNil() {
							resources.Each(func(key, value cty.Value) {
								if value.Type() == cty.String && strings.Contains(value.AsString(), ("*")) {
									set.AddResult().
										WithDescription("Resource '%s' a policy with KMS actions for all KMS keys.", policyDocumentBlock.FullName()).
										WithBlock(policyDocumentBlock).
										WithAttribute(resources)
								}
							})

						}
					}
				}
			}
		},
	})
}

func checkAWS097PolicyJSON(set result.Set, resourceBlock block.Block, policyAttr block.Attribute) {
	var document PolicyDocument
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
					set.AddResult().
						WithDescription("Resource '%s' a policy with KMS actions for all KMS keys.", resourceBlock.FullName()).
						WithAttribute(policyAttr)
					return
				}
			}
		}
	}
}
