package neptune

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogExport = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0075",
		Provider:    provider.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-log-export",
		Summary:     "Neptune logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to Neptune",
		Resolution:  "Enable export logs",
		Explanation: `Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.Logging.Audit.IsFalse() {
				results.Add(
					"Cluster does not have audit logging enabled.",
					&cluster,
					cluster.Logging.Audit,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
