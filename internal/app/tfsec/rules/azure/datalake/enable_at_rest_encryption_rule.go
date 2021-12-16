package datalake

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/datalake"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_data_lake_store"},
		Base:           datalake.CheckEnableAtRestEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("encryption_state") {
				return
			}

			encryptionStateAttr := resourceBlock.GetAttribute("encryption_state")
			if encryptionStateAttr.Equals("Disabled") {
				results.Add("Resource defines an unencrypted data lake store.", encryptionStateAttr)
			}

			return results
		},
	})
}
