package secrets

 generator-locked
import (
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GEN002",
		Base: rules.Register(rules.Rule{
			Service:    "secrets",
			ShortCode:  "sensitive-in-local",
			Summary:    "Potentially sensitive data stored in local value.",
			Impact:     "Local value could be leaking secrets",
			Resolution: "Don't include sensitive data in locals",
			Explanation: `
 Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.
 
 *NOTE: It is also recommended to store your Terraform state in an encrypted form.*
 `,
			Provider: provider.GeneralProvider,
			Severity: severity.Critical,
		}, nil),
		Links: []string{
			"https://www.terraform.io/docs/state/sensitive-data.html",
		},
		RequiredTypes: []string{"locals"},
		BadExample: []string{`
 locals {
   password = "p4ssw0rd"
 }
 
 resource "evil_corp" "bad_example" {
 	root_password = local.password
 }
 `},
		GoodExample: []string{`
 variable "password" {
   description = "The root password for our VM"
   type        = string
 }
 
 resource "evil_corp" "good_example" {
 	root_password = var.password
 }
 `},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			for _, attribute := range resourceBlock.GetAttributes() {
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.IsResolvable() {
						results.Add(
							"Local has a name which indicates it may be sensitive, and contains a value which is defined inside the project.",
							attribute,
						)
					}
				}
			}
			return
		},
	})
}
