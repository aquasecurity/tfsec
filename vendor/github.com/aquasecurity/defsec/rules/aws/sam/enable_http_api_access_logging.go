package sam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableHttpApiAccessLogging = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0116",
		Provider:    provider.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-http-api-access-logging",
		Summary:     "SAM HTTP API stages for V1 and V2 should have access logging enabled",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for API Gateway stages",
		Explanation: `API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-httpapi.html#sam-httpapi-accesslogsettings",
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableHttpApiAccessLoggingGoodExamples,
			BadExamples:         cloudFormationEnableHttpApiAccessLoggingBadExamples,
			Links:               cloudFormationEnableHttpApiAccessLoggingLinks,
			RemediationMarkdown: cloudFormationEnableHttpApiAccessLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, api := range s.AWS.SAM.HttpAPIs {
			if api.IsUnmanaged() {
				continue
			}

			if api.AccessLogging.CloudwatchLogGroupARN.IsEmpty() {
				results.Add(
					"Access logging is not configured.",
					&api,
					api.AccessLogging.CloudwatchLogGroupARN,
				)
			} else {
				results.AddPassed(&api)
			}
		}

		return
	},
)
