package iam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
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
		Terraform:   &rules.EngineMetadata{
            GoodExamples:        terraformEnforceMfaGoodExamples,
            BadExamples:         terraformEnforceMfaBadExamples,
            Links:               terraformEnforceMfaLinks,
            RemediationMarkdown: terraformEnforceMfaRemediationMarkdown,
        },
        Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		return
	},
)
