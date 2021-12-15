package monitor

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_monitor_log_profile"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("retention_policy") {
				return
			}

			retentionPolicyBlock := resourceBlock.GetBlock("retention_policy")

			if retentionPolicyBlock.MissingChild("enabled") {
				results.Add("Resource does not enable retention policy", retentionPolicyBlock)
				return
			}

			if retentionPolicyBlock.MissingChild("days") {
				results.Add("Resource does not retention policy days set", retentionPolicyBlock)
				return
			}

			daysAttr := retentionPolicyBlock.GetAttribute("days")
			if daysAttr.LessThan(356) {
				results.Add("Resource has retention period of less than 365 days", daysAttr)
			}
			return results
		},
	})
}
