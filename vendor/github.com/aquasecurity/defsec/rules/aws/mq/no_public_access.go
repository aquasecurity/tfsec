package mq

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0072",
		Provider:    provider.AWSProvider,
		Service:     "mq",
		ShortCode:   "no-public-access",
		Summary:     "Ensure MQ Broker is not publicly exposed",
		Impact:      "Publicly accessible MQ Broker may be vulnerable to compromise",
		Resolution:  "Disable public access when not required",
		Explanation: `Public access of the MQ broker should be disabled and only allow routes to applications that require access.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.PublicAccess.IsTrue() {
				results.Add(
					"Broker has public access enabled.",
					&broker,
					broker.PublicAccess,
				)
			} else {
				results.AddPassed(&broker)
			}
		}
		return
	},
)
