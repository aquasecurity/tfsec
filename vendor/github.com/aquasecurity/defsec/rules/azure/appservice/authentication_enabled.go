package appservice

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAuthenticationEnabled = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "appservice",
		ShortCode:   "authentication-enabled",
		Summary:     "App Service authentication is activated",
		Impact:      "Anonymous HTTP requests will be accepted",
		Resolution:  "Enable authentication to prevent anonymous request being accepted",
		Explanation: `Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.Authentication.Enabled.IsFalse() {
				results.Add(
					"App service does not have authentication enabled.",
					service.Authentication.Enabled,
				)
			}
		}
		return
	},
)
