package monitor

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "monitor",
		ShortCode: "capture-all-activities",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure log profile captures all activities",
			Explanation: `Log profiles should capture all categories to ensure that all events are logged`,
			Impact:      "Log profile must capture all activity to be able to ensure that all relevant information possible is available for an investigation",
			Resolution:  "Configure log profile to capture all activities",
			BadExample: []string{`
resource "azurerm_monitor_log_profile" "bad_example" {
  name = "bad_example"

  categories = []

  retention_policy {
    enabled = true
    days    = 7
  }
}
`},
			GoodExample: []string{`
resource "azurerm_monitor_log_profile" "good_example" {
  name = "good_example"

  categories = [
	  "Action",
	  "Delete",
	  "Write",
  ]

  retention_policy {
    enabled = true
    days    = 365
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#categories",
				"https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
				"https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_monitor_log_profile"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			categoriesAttr := resourceBlock.GetAttribute("categories")
			if categoriesAttr.IsNil() || categoriesAttr.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' does not have required categories", resourceBlock.FullName())
				return
			}

			for _, category := range []string{"Action", "Write", "Delete"} {
				if !categoriesAttr.Contains(category) {
					set.AddResult().
						WithDescription("Resource '%s' is missing '%s' category", resourceBlock.FullName(), category).
						WithAttribute(categoriesAttr)
				}
			}

		},
	})
}
