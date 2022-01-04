package datalake

import (
	"github.com/aquasecurity/defsec/rules/azure/datalake"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU004",
		BadExample: []string{`
 resource "azurerm_data_lake_store" "bad_example" {
 	encryption_state = "Disabled"
 }`},
		GoodExample: []string{`
 resource "azurerm_data_lake_store" "good_example" {
 	encryption_state = "Enabled"
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_lake_store",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_data_lake_store"},
		Base:           datalake.CheckEnableAtRestEncryption,
	})
}
