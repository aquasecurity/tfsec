package athena

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoEncryptionOverride = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0007",
		Provider:    provider.AWSProvider,
		Service:     "athena",
		ShortCode:   "no-encryption-override",
		Summary:     "Athena workgroups should enforce configuration to prevent client disabling encryption",
		Impact:      "Clients can ignore encryption requirements",
		Resolution:  "Enforce the configuration to prevent client overrides",
		Explanation: `Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.`,
		Links: []string{
			"https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, workgroup := range s.AWS.Athena.Workgroups {
			if !workgroup.IsManaged() {
				continue
			}
			if workgroup.EnforceConfiguration.IsFalse() {
				results.Add(
					"The workgroup configuration is not enforced.",
					&workgroup,
					workgroup.EnforceConfiguration,
				)
			}
		}
		return
	},
)
