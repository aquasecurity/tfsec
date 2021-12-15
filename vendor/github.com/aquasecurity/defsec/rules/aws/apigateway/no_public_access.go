package apigateway

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		AVDID:       "",
		Provider:    provider.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "no-public-access",
		Summary:     "No unauthorized access to API Gateway methods",
		Impact:      "API gateway methods can be accessed without authorization.",
		Resolution:  "Use and authorization method or require API Key",
		Explanation: `API Gateway methods should generally be protected by authorization or api key. OPTION verb calls can be used without authorization`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, api := range s.AWS.APIGateway.APIs {
			if !api.IsManaged() || api.ProtocolType.NotEqualTo(apigateway.ProtocolTypeREST) {
				continue
			}
			for _, method := range api.RESTMethods {
				if method.HTTPMethod.EqualTo("OPTION") {
					continue
				}
				if method.APIKeyRequired.IsTrue() {
					continue
				}
				if method.AuthorizationType.EqualTo(apigateway.AuthorizationNone) {
					results.Add(
						"Authorization is not enabled for this method.",
						&method,
						method.AuthorizationType,
					)
				} else {
					results.AddPassed(&method)
				}
			}
		}
		return
	},
)
