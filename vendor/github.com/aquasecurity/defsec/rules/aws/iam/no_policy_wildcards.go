package iam

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/liamg/iamgo"
)

var CheckNoPolicyWildcards = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0057",
		Provider:    provider.AWSProvider,
		Service:     "iam",
		ShortCode:   "no-policy-wildcards",
		Summary:     "IAM policy should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPolicyWildcardsGoodExamples,
			BadExamples:         terraformNoPolicyWildcardsBadExamples,
			Links:               terraformNoPolicyWildcardsLinks,
			RemediationMarkdown: terraformNoPolicyWildcardsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoPolicyWildcardsBadExamples,
			Links:               cloudFormationNoPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, policy := range s.AWS.IAM.Policies {
			results = checkPolicy(policy.Document, results)
		}
		for _, group := range s.AWS.IAM.Groups {
			for _, policy := range group.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, user := range s.AWS.IAM.Users {
			for _, policy := range user.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, role := range s.AWS.IAM.Roles {
			for _, policy := range role.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		return results
	},
)

func checkPolicy(src types.StringValue, results rules.Results) rules.Results {
	policy, err := iamgo.ParseString(src.Value())
	if err != nil {
		return results
	}
	for _, statement := range policy.Statement {
		results = checkStatement(src, statement, results)
	}
	return results
}

//nolint
func checkStatement(src types.StringValue, statement iamgo.Statement, results rules.Results) rules.Results {
	if statement.Effect != iamgo.EffectAllow {
		return results
	}
	var actions []string
	var resources []string
	for _, action := range statement.Action {
		if strings.Contains(action, "*") {
			actions = append(actions, action)
		} else {
			results.AddPassed(src)
		}
	}
	for _, resource := range statement.Resource {
		if strings.Contains(resource, "*") {
			if allowed, action := iam.IsWildcardAllowed(statement.Action...); !allowed {
				if strings.HasSuffix(resource, "/*") && strings.HasPrefix(resource, "arn:aws:s3") {
					continue
				}
				resources = append(resources, fmt.Sprintf("action %s on resource %s", action, resource))
			} else {
				results.AddPassed(src)
			}
		} else {
			results.AddPassed(src)
		}
	}
	if statement.Principal != nil {
		if statement.Principal.All {
			results.Add(
				"IAM policy document uses wildcarded principal.",
				src,
			)
		}
		for _, principal := range statement.Principal.AWS {
			if strings.Contains(principal, "*") {
				results.Add(
					"IAM policy document uses wildcarded principal.",
					src,
				)
			} else {
				results.AddPassed(src)
			}
		}
	}

	if len(resources) == 1 {
		results.Add(
			fmt.Sprintf("IAM policy document uses wildcarded resource for sensitive action(s): %s", resources[0]),
			src,
		)
	} else if len(resources) > 1 {
		results.Add(
			fmt.Sprintf(
				"IAM policy document uses %d wildcarded resources for sensitive action(s): %s",
				len(resources),
				strings.Join(resources, ", "),
			),
			src,
		)
	}

	if len(actions) == 1 {
		results.Add(
			fmt.Sprintf(
				"IAM policy document uses wildcarded action: %s",
				actions[0],
			),
			src,
		)
	} else if len(actions) > 1 {
		results.Add(
			fmt.Sprintf("IAM policy document uses %d wildcarded actions: %s", len(actions), strings.Join(actions, ", ")),
			src,
		)
	}

	return results
}
