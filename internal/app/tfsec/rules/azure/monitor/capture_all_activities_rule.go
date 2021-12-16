package monitor

import (
	"fmt"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/monitor"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_monitor_log_profile"},
		Base:           monitor.CheckCaptureAllActivities,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			categoriesAttr := resourceBlock.GetAttribute("categories")
			if categoriesAttr.IsNil() || categoriesAttr.IsEmpty() {
				results.Add("Resource does not have required categories", resourceBlock)
				return
			}

			for _, category := range []string{"Action", "Write", "Delete"} {
				if !categoriesAttr.Contains(category) {
					results.Add(fmt.Sprintf("Resource is missing '%s' category", category), categoriesAttr)
				}
			}

			return results
		},
	})
}
