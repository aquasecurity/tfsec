package apigateway

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableCacheEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0002",
		Provider:    provider.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-cache-encryption",
		Summary:     "API Gateway must have cache enabled",
		Impact:      "Data stored in the cache that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable cache encryption",
		Explanation: `Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception`,
		Links:       []string{},
		Severity:    severity.Medium,
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
				if stage.RESTMethodSettings.CacheDataEncrypted.IsFalse() {
					results.Add(
						"Cache data is not encrypted.",
						&stage,
						stage.RESTMethodSettings.CacheDataEncrypted,
					)
				} else {
					results.AddPassed(&stage)
				}
			}
		}
		return
	},
)
