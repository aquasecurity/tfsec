package authorization

import (
	"github.com/aquasecurity/defsec/rules/azure/authorization"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 data "azurerm_subscription" "primary" {
 }
 
 resource "azurerm_role_definition" "example" {
   name        = "my-custom-role"
   scope       = data.azurerm_subscription.primary.id
   description = "This is a custom role created via Terraform"
 
   permissions {
     actions     = ["*"]
     not_actions = []
   }
 
   assignable_scopes = [
     "/"
   ]
 }
 `},
		GoodExample: []string{`
 data "azurerm_subscription" "primary" {
 }
 
 resource "azurerm_role_definition" "example" {
   name        = "my-custom-role"
   scope       = data.azurerm_subscription.primary.id
   description = "This is a custom role created via Terraform"
 
   permissions {
     actions     = ["*"]
     not_actions = []
   }
 
   assignable_scopes = [
     data.azurerm_subscription.primary.id,
   ]
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_role_definition",
		},
		Base: authorization.CheckLimitRoleActions,
	})
}
