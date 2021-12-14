package secrets

 generator-locked
import (
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/defsec/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GEN001",
		Base: rules.Register(rules.Rule{
			Service:    "secrets",
			ShortCode:  "sensitive-in-variable",
			Summary:    "Potentially sensitive data stored in \"default\" value of variable.",
			Impact:     "Default values could be exposing sensitive data",
			Resolution: "Don't include sensitive data in variable defaults",
			Explanation: `
 Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.
 
 *NOTE: It is also recommended to store your Terraform state in an encrypted form.*
 `,
			Provider: provider.GeneralProvider,
			Severity: severity.Critical,
		}, nil),
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
			return
		},
	})
}
