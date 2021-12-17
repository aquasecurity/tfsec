package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoSerialPort = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0032",
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-serial-port",
		Summary:     "Disable serial port connectivity for all instances",
		Impact:      "Unrestricted network access to the serial console of the instance",
		Resolution:  "Disable serial port access",
		Explanation: `When serial port access is enabled, the access is not governed by network security rules meaning the port can be exposed publicly.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.EnableSerialPort.IsTrue() {
				results.Add(
					"Instance has serial port enabled.",
					instance.EnableSerialPort,
				)
			}
		}
		return
	},
)
