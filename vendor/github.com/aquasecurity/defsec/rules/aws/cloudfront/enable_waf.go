package cloudfront

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableWaf = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0011",
		Provider:    provider.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "enable-waf",
		Summary:     "CloudFront distribution does not have a WAF in front.",
		Impact:      "Complex web application attacks can more easily be performed without a WAF",
		Resolution:  "Enable WAF for the CloudFront distribution",
		Explanation: `You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.`,
		Links: []string{
			"https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.WAFID.IsEmpty() {
				results.Add(
					"Distribution does not utilise a WAF.",
					&dist,
					dist.WAFID,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
