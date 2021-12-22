package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnforceHttps = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0046",
		Provider:   provider.AWSProvider,
		Service:    "elastic-search",
		ShortCode:  "enforce-https",
		Summary:    "Elasticsearch doesn't enforce HTTPS traffic.",
		Impact:     "HTTP traffic can be intercepted and the contents read",
		Resolution: "Enforce the use of HTTPS for ElasticSearch",
		Explanation: `Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.Endpoint.EnforceHTTPS.IsFalse() {
				results.Add(
					"Domain does not enfroce HTTPS.",
					&domain,
					domain.Endpoint.EnforceHTTPS,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
