package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const AWSIAMPolicyShouldUsePrincipleOfLeastPrivilege = "AWS099"
const AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeDescription = "IAM policy should avoid use of wildcards and instead apply the principle of least privilege"
const AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeImpact = "Overly permissive policies may grant access to sensitive resources"
const AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeResolution = "Specify the exact permissions required, and to which resources they should apply instead of using wildcards."
const AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeExplanation = `
You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.
`
const AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeBadExample = `
resource "aws_iam_role_policy" "test_policy" {
	name = "test_policy"
	role = aws_iam_role.test_role.id

	policy = data.aws_iam_policy_document.s3_policy.json
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
			Service = "s3.amazonaws.com"
			}
		},
		]
	})
}

data "aws_iam_policy_document" "s3_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["s3:*"]
    resources = ["*"]
  }
}
`
const AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeGoodExample = `
resource "aws_iam_role_policy" "test_policy" {
	name = "test_policy"
	role = aws_iam_role.test_role.id

	policy = data.aws_iam_policy_document.s3_policy.json
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
			Service = "s3.amazonaws.com"
			}
		},
		]
	})
}

data "aws_iam_policy_document" "s3_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["s3:GetObject"]
    resources = [aws_s3_bucket.example.arn]
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSIAMPolicyShouldUsePrincipleOfLeastPrivilege,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeDescription,
			Explanation: AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeExplanation,
			Impact:      AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeImpact,
			Resolution:  AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeResolution,
			BadExample:  AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeBadExample,
			GoodExample: AWSIAMPolicyShouldUsePrincipleOfLeastPrivilegeGoodExample,
			Links:       []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_role_policy"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, ctx *hclcontext.Context) {
			policyAttr := resourceBlock.GetAttribute("policy")
			if policyAttr == nil {
				return
			}

			if policyAttr.IsString() {
				checkAWS099PolicyJSON(set, resourceBlock, policyAttr)
				return
			}

			policyDocumentBlock, err := ctx.GetReferencedBlock(policyAttr)
			if err != nil {
				return
			}

			if policyDocumentBlock.Type() != "data" || policyDocumentBlock.TypeLabel() != "aws_iam_policy_document" {
				return
			}

			checkAWS099PolicyDocumentBlock(set, policyDocumentBlock)

		},
	})
}

func checkAWS099PolicyDocumentBlock(set result.Set, policyDocumentBlock block.Block) {

	if statementBlocks := policyDocumentBlock.GetBlocks("statement"); statementBlocks != nil {
		for _, statementBlock := range statementBlocks {

			if statementBlock.HasChild("effect") && statementBlock.GetAttribute("effect").Equals("deny", block.IgnoreCase) {
				continue
			}

			actionsAttr := statementBlock.GetAttribute("actions")
			if actionsAttr != nil && actionsAttr.Contains("*") {
				set.Add(
					result.New(policyDocumentBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a policy with wildcarded actions.", policyDocumentBlock.FullName())).
						WithRange(actionsAttr.Range()).
						WithAttributeAnnotation(actionsAttr),
				)
			}

			resourcesAttr := statementBlock.GetAttribute("resources")
			if resourcesAttr != nil && resourcesAttr.Contains("*") {
				set.Add(
					result.New(policyDocumentBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a policy with wildcarded resources.", policyDocumentBlock.FullName())).
						WithRange(resourcesAttr.Range()).
						WithAttributeAnnotation(resourcesAttr),
				)
			}

			principalsBlock := statementBlock.GetBlock("principals")
			if principalsBlock != nil {
				principalTypeAttr := principalsBlock.GetAttribute("type")
				if principalTypeAttr != nil && principalTypeAttr.Equals("AWS") {
					identifiersAttr := principalsBlock.GetAttribute("identifiers")
					if identifiersAttr != nil {
						for _, ident := range identifiersAttr.ValueAsStrings() {
							if strings.Contains(ident, "*") {
								set.Add(
									result.New(policyDocumentBlock).
										WithDescription(fmt.Sprintf("Resource '%s' defines a policy with wildcarded principal identifiers.", policyDocumentBlock.FullName())).
										WithRange(resourcesAttr.Range()).
										WithAttributeAnnotation(resourcesAttr),
								)
								break
							}
						}
					}
				}
			}

		}
	}
}

func checkAWS099PolicyJSON(set result.Set, resourceBlock block.Block, policyAttr block.Attribute) {
	var document awsIAMPolicyDocument
	if err := json.Unmarshal([]byte(policyAttr.Value().AsString()), &document); err != nil {
		return
	}
	for _, statement := range document.Statements {
		if strings.ToLower(statement.Effect) == "deny" {
			continue
		}
		for _, action := range statement.Action {
			if strings.Contains(action, "*") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a policy with wildcarded actions.", resourceBlock.FullName())).
						WithRange(policyAttr.Range()).
						WithAttributeAnnotation(policyAttr),
				)
			}
		}
		for _, resource := range statement.Resource {
			if strings.Contains(resource, "*") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a policy with wildcarded resources.", resourceBlock.FullName())).
						WithRange(policyAttr.Range()).
						WithAttributeAnnotation(policyAttr),
				)
			}
		}
		for _, identifier := range statement.Principal.AWS {
			if strings.Contains(identifier, "*") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a policy with wildcarded principal identifiers.", resourceBlock.FullName())).
						WithRange(policyAttr.Range()).
						WithAttributeAnnotation(policyAttr),
				)
			}
		}
	}
}
