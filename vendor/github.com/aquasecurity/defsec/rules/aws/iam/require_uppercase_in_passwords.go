package iam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckRequireUppercaseInPasswords = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0061",
		Provider:   provider.AWSProvider,
		Service:    "iam",
		ShortCode:  "require-uppercase-in-passwords",
		Summary:    "IAM Password policy should have requirement for at least one uppercase character.",
		Impact:     "Short, simple passwords are easier to compromise",
		Resolution: "Enforce longer, more complex passwords in the policy",
		Explanation: `,
IAM account password policies should ensure that passwords content including at least one uppercase character.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if !policy.IsManaged() {
			return
		}

		if policy.RequireUppercase.IsFalse() {
			results.Add(
				"Password policy does not require uppercase characters.",
				&policy,
				policy.RequireUppercase,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
