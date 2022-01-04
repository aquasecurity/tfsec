package network

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/network"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
resource "azurerm_network_watcher_flow_log" "bad_watcher" {
	network_watcher_name = "bad_watcher"
	resource_group_name = "resource-group"

	network_security_group_id = azurerm_network_security_group.test.id
	storage_account_id = azurerm_storage_account.test.id
	enabled = true

	retention_policy {
		enabled = true
		days = 7
	}
}
		`},
		GoodExample: []string{`
resource "azurerm_network_watcher_flow_log" "good_watcher" {
	network_watcher_name = "good_watcher"
	resource_group_name = "resource-group"

	network_security_group_id = azurerm_network_security_group.test.id
	storage_account_id = azurerm_storage_account.test.id
	enabled = true

	retention_policy {
		enabled = true
		days = 90
	}
}
	`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#retention_policy",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_watcher_flow_log"},
		Base:           network.CheckRetentionPolicySet,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("retention_policy") {
				results.Add("Resource is missing the required retention policy block", resourceBlock)
				return
			}

			retentionPolicyBlock := resourceBlock.GetBlock("retention_policy")
			if retentionPolicyBlock.MissingChild("enabled") || retentionPolicyBlock.MissingChild("days") {
				results.Add("Resource is missing the required attributes retention policy block", retentionPolicyBlock)
				return
			}

			enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
			daysAttr := retentionPolicyBlock.GetAttribute("days")

			if enabledAttr.IsFalse() {
				results.Add("Resource has retention policy turned off", enabledAttr)
			}

			if daysAttr.LessThan(90) {
				results.Add("Resource has retention policy period of less than 90 days", daysAttr)
			}
			return results
		},
	})
}
