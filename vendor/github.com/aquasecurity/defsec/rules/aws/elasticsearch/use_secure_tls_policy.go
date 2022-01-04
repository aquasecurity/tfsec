package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0126",
		Provider:    provider.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "Elasticsearch domain endpoint is using outdated TLS policy.",
		Impact:      "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution:  "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.Endpoint.TLSPolicy.NotEqualTo("Policy-Min-TLS-1-2-2019-07") {
				results.Add(
					"Domain does not have a secure TLS policy.",
					&domain,
					domain.Endpoint.TLSPolicy,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
