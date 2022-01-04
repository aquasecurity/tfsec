package secrets

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/general/secrets"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GEN001",
		BadExample: []string{`
 variable "password" {
   description = "The root password for our VM"
   type        = string
   default     = "p4ssw0rd"
 }
 
 resource "evil_corp" "virtual_machine" {
 	root_password = var.password
 }
 `},
		GoodExample: []string{`
 variable "password" {
   description = "The root password for our VM"
   type        = string
 }
 
 resource "evil_corp" "virtual_machine" {
 	root_password = var.password
 }
 `},
		Links: []string{
			"https://www.terraform.io/docs/state/sensitive-data.html",
		},
		RequiredTypes: []string{"variable"},
		Base:          secrets.CheckNotExposed,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if len(resourceBlock.Labels()) == 0 || !security.IsSensitiveAttribute(resourceBlock.TypeLabel()) {
				return
			}

			for _, attribute := range resourceBlock.GetAttributes() {
				if attribute.Name() == "default" {
					if attribute.Type() == cty.String && attribute.IsResolvable() {
						results.Add(
							"Variable includes a potentially sensitive default value.",
							attribute,
						)
					}
				}
			}
			return results
		},
	})
}
