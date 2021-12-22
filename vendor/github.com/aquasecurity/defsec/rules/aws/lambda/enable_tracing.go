package lambda

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableTracing = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0066",
		Provider:    provider.AWSProvider,
		Service:     "lambda",
		ShortCode:   "enable-tracing",
		Summary:     "Lambda functions should have X-Ray tracing enabled",
		Impact:      "WIthout full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all function activity. This will allow for identifying bottlenecks, slow downs and timeouts.`,
		Links: []string{
			"https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, function := range s.AWS.Lambda.Functions {
			if function.Tracing.Mode.NotEqualTo(lambda.TracingModeActive) && function.Tracing.Mode.NotEqualTo(lambda.TracingModePassThrough) {
				results.Add(
					"Function does not have tracing enabled.",
					&function,
					function.Tracing.Mode,
				)
			} else {
				results.AddPassed(&function)
			}
		}
		return
	},
)
