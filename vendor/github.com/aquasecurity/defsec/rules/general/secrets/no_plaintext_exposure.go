package secrets

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNotExposed = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GEN-0004",
		Provider:    provider.GeneralProvider,
		Service:     "secrets",
		ShortCode:   "no-plaintext-exposure",
		Summary:     "Secret/sensitive data should not be exposed in plaintext.",
		Impact:      "Sensitive data can be leaked to unauthorised people or systems.",
		Resolution:  "Remove plaintext secrets and encrypt them within a secrets manager instead.",
		Explanation: `Plaintext secrets kept in source code or similar media mean sensitive data is exposed to any users/systems with access to the source code.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPlaintextExposureGoodExamples,
			BadExamples:         terraformNoPlaintextExposureBadExamples,
			Links:               terraformNoPlaintextExposureLinks,
			RemediationMarkdown: terraformNoPlaintextExposureRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		// (exposure detection is handled by individual tools e.g. tfsec)
		return
	},
)
