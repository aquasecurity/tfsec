package elb

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAlbNotPublic = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0053",
		Provider:    provider.AWSProvider,
		Service:     "elb",
		ShortCode:   "alb-not-public",
		Summary:     "Load balancer is exposed to the internet.",
		Impact:      "The load balancer is exposed on the internet",
		Resolution:  "Switch to an internal load balancer or add a tfsec ignore",
		Explanation: `There are many scenarios in which you would want to expose a load balancer to the wider internet, but this check exists as a warning to prevent accidental exposure of internal assets. You should ensure that this resource should be exposed publicly.`,
		Links:       []string{},
		Severity:    severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, lb := range s.AWS.ELB.LoadBalancers {
			if lb.Type.EqualTo(elb.TypeGateway) || !lb.IsManaged() {
				continue
			}
			if lb.Internal.IsFalse() {
				results.Add(
					"Load balancer is exposed publicly.",
					&lb,
					lb.Internal,
				)
			} else {
				results.AddPassed(&lb)
			}
		}
		return
	},
)
