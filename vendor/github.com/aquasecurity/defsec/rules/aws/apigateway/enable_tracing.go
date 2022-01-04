package apigateway

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableTracing = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0003",
		Provider:    provider.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-tracing",
		Summary:     "API Gateway must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, api := range s.AWS.APIGateway.APIs {
			if !api.IsManaged() || api.ProtocolType.NotEqualTo(apigateway.ProtocolTypeREST) {
				continue
			}
			for _, stage := range api.Stages {
				if !stage.IsManaged() || stage.Version.NotEqualTo(1) {
					continue
				}
				if stage.XRayTracingEnabled.IsFalse() {
					results.Add(
						"X-Ray tracing is not enabled,",
						&stage,
						stage.XRayTracingEnabled,
					)
				} else {
					results.AddPassed(&stage)
				}
			}
		}
		return
	},
)
