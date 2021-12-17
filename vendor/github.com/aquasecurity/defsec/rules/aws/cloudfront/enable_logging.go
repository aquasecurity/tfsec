package cloudfront

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogging = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0010",
		Provider:    provider.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "enable-logging",
		Summary:     "Cloudfront distribution should have Access Logging configured",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for CloudFront distributions",
		Explanation: `You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.Logging.Bucket.IsEmpty() {
				results.Add(
					"Distribution does not have logging enabled.",
					&dist,
					dist.Logging.Bucket,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
