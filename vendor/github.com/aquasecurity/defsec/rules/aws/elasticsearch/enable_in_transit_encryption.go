package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0043",
		Provider:    provider.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Elasticsearch domain uses plaintext traffic for node to node communication.",
		Impact:      "In transit data between nodes could be read if intercepted",
		Resolution:  "Enable encrypted node to node communication",
		Explanation: `Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.TransitEncryption.Enabled.IsFalse() {
				results.Add(
					"Domain does not have in-transit encryption enabled.",
					&domain,
					domain.TransitEncryption.Enabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
