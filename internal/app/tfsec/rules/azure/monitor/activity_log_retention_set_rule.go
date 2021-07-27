package monitor

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "monitor",
		ShortCode: "activity-log-retention-set",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure the activity retention log is set to at least a year",
			Explanation: `The average time to detect a breach is up to 210 days, to ensure that all the information required for an effective investigation is available, the retention period should allow for delayed starts to investigating.`,
			Impact:      "Short life activity logs can lead to missing records when investigating a breach",
			Resolution:  "Set a retention period that will allow for delayed investigation",
			BadExample: []string{`
resource "azurerm_monitor_log_profile" "bad_example" {
  name = "bad_example"

  retention_policy {
    enabled = true
    days    = 7
  }
}
`},
			GoodExample: []string{`
resource "azurerm_monitor_log_profile" "good_example" {
  name = "good_example"

  retention_policy {
    enabled = true
    days    = 365
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#retention_policy",
				"https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_monitor_log_profile"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("retention_policy") {
				return
			}

			retentionPolicyBlock := resourceBlock.GetBlock("retention_policy")

			if retentionPolicyBlock.MissingChild("enabled") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not enable retention policy", resourceBlock.FullName())).
						WithRange(retentionPolicyBlock.Range()),
				)
				return
			}

			if retentionPolicyBlock.MissingChild("days") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not retention policy days set", resourceBlock.FullName())).
						WithRange(retentionPolicyBlock.Range()),
				)
				return
			}

			daysAttr := retentionPolicyBlock.GetAttribute("days")
			if daysAttr.LessThan(356) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has retention period of less than 365 days", resourceBlock.FullName())).
						WithRange(daysAttr.Range()).
						WithAttributeAnnotation(daysAttr),
				)
			}
		},
	})
}
