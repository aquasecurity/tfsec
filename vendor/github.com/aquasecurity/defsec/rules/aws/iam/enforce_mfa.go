package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/liamg/iamgo"
)

var CheckEnforceMFA = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0123",
		Provider:   provider.AWSProvider,
		Service:    "iam",
		ShortCode:  "enforce-mfa",
		Summary:    "IAM Groups should have MFA enforcement activated.",
		Impact:     "User accounts are more vulnerable to compromise without multi factor authentication activated",
		Resolution: "Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced",
		Explanation: `
IAM user accounts should be protected with multi factor authentication to add safe guards to password compromise.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnforceMfaGoodExamples,
			BadExamples:         terraformEnforceMfaBadExamples,
			Links:               terraformEnforceMfaLinks,
			RemediationMarkdown: terraformEnforceMfaRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {

		for _, group := range s.AWS.IAM.Groups {
			var mfaEnforced bool
			for _, policy := range group.Policies {
				document, err := iamgo.ParseString(policy.Document.Value())
				if err != nil {
					continue
				}
				for _, statement := range document.Statement {
					for _, condition := range statement.Condition {
						if strings.EqualFold(condition.Key, "aws:MultiFactorAuthPresent") {
							mfaEnforced = true
							break
						}
					}
				}
			}
			if !mfaEnforced {
				results.Add("Multi-Factor Authentication is not enforced for group", &group)
			}
		}

		return
	},
)
