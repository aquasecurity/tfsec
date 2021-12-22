package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableDomainEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0048",
		Provider:    provider.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "enable-domain-encryption",
		Summary:     "Elasticsearch domain isn't encrypted at rest.",
		Impact:      "Data will be readable if compromised",
		Resolution:  "Enable ElasticSearch domain encryption",
		Explanation: `You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.AtRestEncryption.Enabled.IsFalse() {
				results.Add(
					"Domain does not have at-rest encryption enabled.",
					&domain,
					domain.AtRestEncryption.Enabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
