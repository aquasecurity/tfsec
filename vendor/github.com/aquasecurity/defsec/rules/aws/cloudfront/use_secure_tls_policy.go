package cloudfront

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0013",
		Provider:    provider.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "CloudFront distribution uses outdated SSL/TLS protocols.",
		Impact:      "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution:  "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.ViewerCertificate.MinimumProtocolVersion.NotEqualTo(cloudfront.ProtocolVersionTLS1_2) {
				results.Add(
					"Distribution allows unencrypted communications.",
					&dist,
					dist.ViewerCertificate.MinimumProtocolVersion,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
