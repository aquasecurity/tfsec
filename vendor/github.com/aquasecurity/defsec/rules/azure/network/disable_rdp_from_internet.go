package network

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDisableRdpFromInternet = rules.Register(
	rules.Rule{
                AVDID: "AVD-AZU-0048",
		Provider:   provider.AzureProvider,
		Service:    "network",
		ShortCode:  "disable-rdp-from-internet",
		Summary:    "RDP access should not be accessible from the Internet, should be blocked on port 3389",
		Impact:     "Anyone from the internet can potentially RDP onto an instance",
		Resolution: "Block RDP port from internet",
		Explanation: `RDP access can be configured on either the network security group or in the network security group rule.

RDP access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any). Consider using the Azure Bastion Service.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, group := range s.Azure.Network.SecurityGroups {
			for _, rule := range group.InboundAllowRules {
				for _, ports := range rule.DestinationPortRanges {
					if portRangeContains(ports.Value(), 3389) {
						for _, ip := range rule.SourceAddresses {
							if cidr.IsPublic(ip.Value()) {
								results.Add(
									"Security group rule allows ingress to RDP port from public internet.",
									ip,
								)
							}
						}
					}
				}
			}
		}
		return
	},
)

func portRangeContains(r string, port int64) bool {
	if strings.Contains(r, "-") {
		parts := strings.Split(r, "-")
		start, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return false
		}
		end, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return false
		}
		return port >= start && port <= end
	}

	single, err := strconv.ParseInt(r, 10, 64)
	if err != nil {
		return false
	}
	return single == port
}
