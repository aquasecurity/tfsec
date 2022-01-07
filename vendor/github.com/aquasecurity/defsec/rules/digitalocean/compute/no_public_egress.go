package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicEgress = rules.Register(
	rules.Rule{
                AVDID: "AVD-DIG-0003",
		Provider:    provider.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "no-public-egress",
		Summary:     "The firewall has an outbound rule with open access",
		Impact:      "The port is exposed for ingress from the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/",
		},
		Terraform:   &rules.EngineMetadata{
            GoodExamples:        terraformNoPublicEgressGoodExamples,
            BadExamples:         terraformNoPublicEgressBadExamples,
            Links:               terraformNoPublicEgressLinks,
            RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
        },
        Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
				)
			}
		}
		return
	},
)
