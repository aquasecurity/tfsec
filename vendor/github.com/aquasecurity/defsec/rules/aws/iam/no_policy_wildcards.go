package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
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
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {

		var documents []iam.PolicyDocument
		for _, policy := range s.AWS.IAM.Policies {
			documents = append(documents, policy.Document)
		}
		for _, policy := range s.AWS.IAM.GroupPolicies {
			documents = append(documents, policy.Document)
		}
		for _, policy := range s.AWS.IAM.UserPolicies {
			documents = append(documents, policy.Document)
		}
		for _, policy := range s.AWS.IAM.RolePolicies {
			documents = append(documents, policy.Document)
		}

		for _, document := range documents {
			for _, statement := range document.Statements {
				results = checkStatement(document, statement, results)
			}
		}
		return
	},
)

func checkStatement(document iam.PolicyDocument, statement iam.PolicyDocumentStatement, results rules.Results) rules.Results {
	if strings.ToLower(statement.Effect) == "deny" {
		return results
	}
	for _, action := range statement.Action {
		if strings.Contains(action, "*") {
			results.Add(
				"IAM policy document uses wildcarded action.",
				document,
			)
		} else {
			results.AddPassed(&document)
		}
	}
	for _, resource := range statement.Resource {
		if strings.Contains(resource, "*") && !iam.IsWildcardAllowed(statement.Action...) {
			results.Add(
				"IAM policy document uses wildcarded resource for sensitive action(s).",
				document,
			)
		} else {
			results.AddPassed(&document)
		}
	}
	for _, principal := range statement.Principal.AWS {
		if strings.Contains(principal, "*") {
			results.Add(
				"IAM policy document uses wildcarded principal.",
				document,
			)
		} else {
			results.AddPassed(&document)
		}
	}
	return results
}
