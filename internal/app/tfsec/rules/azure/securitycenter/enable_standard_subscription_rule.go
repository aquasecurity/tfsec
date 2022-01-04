package securitycenter

import (
	"github.com/aquasecurity/defsec/rules/azure/securitycenter"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "azurerm_security_center_subscription_pricing" "bad_example" {
   tier          = "Free"
   resource_type = "VirtualMachines"
 }
 `},
		GoodExample: []string{`
 resource "azurerm_security_center_subscription_pricing" "good_example" {
   tier          = "Standard"
   resource_type = "VirtualMachines"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_security_center_subscription_pricing"},
		Base:           securitycenter.CheckEnableStandardSubscription,
	})
}
