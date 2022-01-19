package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/owenrumney/squealer/pkg/squealer"
)

var scanner = squealer.NewStringScanner()

var CheckNoSecretsInCustomData = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AZU-0037",
		Provider:    provider.AzureProvider,
		Service:     "compute",
		ShortCode:   "no-secrets-in-custom-data",
		Summary:     "Ensure that no sensitive credentials are exposed in VM custom_data",
		Impact:      "Sensitive credentials in custom_data can be leaked",
		Resolution:  "Don't use sensitive credentials in the VM custom_data",
		Explanation: `When creating Azure Virtual Machines, custom_data is used to pass start up information into the EC2 instance. This custom_dat must not contain access key credentials.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoSecretsInCustomDataGoodExamples,
			BadExamples:         terraformNoSecretsInCustomDataBadExamples,
			Links:               terraformNoSecretsInCustomDataLinks,
			RemediationMarkdown: terraformNoSecretsInCustomDataRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, vm := range s.Azure.Compute.LinuxVirtualMachines {
			if result := scanner.Scan(vm.CustomData.Value()); result.TransgressionFound {
				results.Add(
					"Virtual machine includes secret(s) in custom data.",
					vm.CustomData,
				)
			}
		}
		for _, vm := range s.Azure.Compute.WindowsVirtualMachines {
			if result := scanner.Scan(vm.CustomData.Value()); result.TransgressionFound {
				results.Add(
					"Virtual machine includes secret(s) in custom data.",
					vm.CustomData,
				)
			}
		}
		return
	},
)
