package cloudtrail

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAllRegions = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0014",
		Provider:    provider.AWSProvider,
		Service:     "cloudtrail",
		ShortCode:   "enable-all-regions",
		Summary:     "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed",
		Impact:      "Activity could be happening in your account in a different region",
		Resolution:  "Enable Cloudtrail in all regions",
		Explanation: `When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operting in.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.IsMultiRegion.IsFalse() {
				results.Add(
					"Trail is not enabled across all regions.",
					&trail,
					trail.IsMultiRegion,
				)
			} else {
				results.AddPassed(&trail)
			}
		}
		return
	},
)
