package ecr

import (
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0032",
		Provider:    provider.AWSProvider,
		Service:     "ecr",
		ShortCode:   "no-public-access",
		Summary:     "ECR repository policy must block public access",
		Impact:      "Risk of potential data leakage of sensitive artifacts",
		Resolution:  "Do not allow public access in the policy",
		Explanation: `Allowing public access to the ECR repository risks leaking sensitive of abusable information`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicAccessGoodExamples,
			BadExamples:         cloudFormationNoPublicAccessBadExamples,
			Links:               cloudFormationNoPublicAccessLinks,
			RemediationMarkdown: cloudFormationNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.IsUnmanaged() {
				continue
			}
			for _, policyDocument := range repo.Policies {
				policy := policyDocument.Document.Parsed
				statements, _ := policy.Statements()
				for _, statement := range statements {
					var hasECRAction bool
					actions, _ := statement.Actions()
					for _, action := range actions {
						if strings.HasPrefix(action, "ecr:") {
							hasECRAction = true
							break
						}
					}
					if !hasECRAction {
						continue
					}
					var foundIssue bool
					principals, _ := statement.Principals()
					if all, r := principals.All(); all {
						foundIssue = true
						results.Add(
							"Policy provides public access to the ECR repository.",
							policyDocument.Document.MetadataFromIamGo(statement.Range(), r),
						)
					} else {
						accounts, r := principals.AWS()
						for _, account := range accounts {
							if account == "*" {
								foundIssue = true
								results.Add(
									"Policy provides public access to the ECR repository.",
									policyDocument.Document.MetadataFromIamGo(statement.Range(), r),
								)
							}
							continue
						}
					}
					if foundIssue {
						results.AddPassed(&repo)
					}
				}
			}
		}
		return
	},
)
