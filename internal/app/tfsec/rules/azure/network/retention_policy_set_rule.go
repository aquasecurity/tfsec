package network

import (
	"github.com/aquasecurity/defsec/rules/azure/network"
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
		days = 365
	}
}
	`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#retention_policy",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_watcher_flow_log"},
		Base:           network.CheckRetentionPolicySet,
	})
}
