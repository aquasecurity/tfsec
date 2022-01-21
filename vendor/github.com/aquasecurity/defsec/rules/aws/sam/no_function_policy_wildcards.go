package sam

import (
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/iamgo"
)

var CheckNoFunctionPolicyWildcards = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0114",
		Provider:    provider.AWSProvider,
		Service:     "sam",
		ShortCode:   "no-function-policy-wildcards",
		Summary:     "Function policies should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-policies",
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoFunctionPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoFunctionPolicyWildcardsBadExamples,
			Links:               cloudFormationNoFunctionPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoFunctionPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {

		for _, function := range s.AWS.SAM.Functions {
			if function.IsUnmanaged() {
				continue
			}

			for _, document := range function.Policies {
				policy, err := iamgo.ParseString(document.Value())
				if err != nil {
					continue
				}
				for _, statement := range policy.Statement {
					results = checkStatement(document, statement, results)
				}
			}
		}
		return
	},
)

func checkStatement(document types.StringValue, statement iamgo.Statement, results rules.Results) rules.Results {
	if statement.Effect != iamgo.EffectAllow {
		return results
	}
	for _, action := range statement.Action {
		if strings.Contains(action, "*") {
			results.Add(
				"Policy document uses a wildcard action.",
				document,
			)
		} else {
			results.AddPassed(document)
		}
	}
	for _, resource := range statement.Resource {
		if strings.Contains(resource, "*") && !iam.IsWildcardAllowed(statement.Action...) {
			if strings.HasSuffix(resource, "/*") && strings.HasPrefix(resource, "arn:aws:s3") {
				continue
			}
			results.Add(
				"Policy document uses a wildcard resource for sensitive action(s).",
				document,
			)
		} else {
			results.AddPassed(document)
		}
	}
	if statement.Principal.All {
		results.Add(
			"Policy document uses a wildcard principal.",
			document,
		)
	}
	for _, principal := range statement.Principal.AWS {
		if strings.Contains(principal, "*") {
			results.Add(
				"Policy document uses a wildcard principal.",
				document,
			)
		} else {
			results.AddPassed(document)
		}
	}
	return results
}
