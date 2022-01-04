package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableDomainLogging = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0042",
		Provider:   provider.AWSProvider,
		Service:    "elastic-search",
		ShortCode:  "enable-domain-logging",
		Summary:    "Domain logging should be enabled for Elastic Search domains",
		Impact:     "Logging provides vital information about access and usage",
		Resolution: "Enable logging for ElasticSearch domains",
		Explanation: `Amazon ES exposes four Elasticsearch logs through Amazon CloudWatch Logs: error logs, search slow logs, index slow logs, and audit logs. 

Search slow logs, index slow logs, and error logs are useful for troubleshooting performance and stability issues. 

Audit logs track user activity for compliance purposes. 

All the logs are disabled by default.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.LogPublishing.AuditEnabled.IsFalse() {
				results.Add(
					"Domain audit logging is not enabled.",
					&domain,
					domain.LogPublishing.AuditEnabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
