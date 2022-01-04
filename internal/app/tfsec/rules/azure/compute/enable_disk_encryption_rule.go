package compute

import (
	"github.com/aquasecurity/defsec/rules/azure/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU003",
		BadExample: []string{`
 resource "azurerm_managed_disk" "bad_example" {
 	encryption_settings {
 		enabled = false
 	}
 }`},
		GoodExample: []string{`
 resource "azurerm_managed_disk" "good_example" {
 	encryption_settings {
 		enabled = true
 	}
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_managed_disk"},
		Base:           compute.CheckEnableDiskEncryption,
	})
}
