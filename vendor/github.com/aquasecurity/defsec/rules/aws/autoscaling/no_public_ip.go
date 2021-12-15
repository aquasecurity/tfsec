package autoscaling

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicIp = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0009",
		Provider:    provider.AWSProvider,
		Service:     "autoscaling",
		ShortCode:   "no-public-ip",
		Summary:     "Launch configuration should not have a public IP address.",
		Impact:      "The instance or configuration is publicly accessible",
		Resolution:  "Set the instance to not be publicly accessible",
		Explanation: `You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, launchConfig := range s.AWS.Autoscaling.LaunchConfigurations {
			if launchConfig.AssociatePublicIP.IsTrue() {
				results.Add(
					"Launch configuration associates public IP address.",
					&launchConfig,
					launchConfig.AssociatePublicIP,
				)
			} else {
				results.AddPassed(&launchConfig)
			}
		}
		return
	},
)
