package documentdb

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogExport = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0020",
		Provider:    provider.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "enable-log-export",
		Summary:     "DocumentDB logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to the DocumentDB",
		Resolution:  "Enable export logs",
		Explanation: `Document DB does not have auditing by default. To ensure that you are able to accurately audit the usage of your DocumentDB cluster you should enable export logs.`,
		Links: []string{
			"https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			var hasAudit bool
			var hasProfiler bool

			for _, log := range cluster.EnabledLogExports {
				if log.EqualTo(documentdb.LogExportAudit) {
					hasAudit = true
				}
				if log.EqualTo(documentdb.LogExportProfiler) {
					hasProfiler = true
				}
			}
			if !hasAudit {
				results.Add(
					"CloudWatch audit log exports are not enabled.",
					cluster,
				)
			} else {
				results.AddPassed(&cluster)
			}
			if !hasProfiler {
				results.Add(
					"CloudWatch profiler log exports are not enabled.",
					cluster,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
