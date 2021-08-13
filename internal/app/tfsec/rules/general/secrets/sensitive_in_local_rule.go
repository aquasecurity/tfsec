package secrets

// generator-locked
import (
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GEN002",
		Service:   "secrets",
		ShortCode: "sensitive-in-local",
		Documentation: rule.RuleDocumentation{
			Summary:    "Potentially sensitive data stored in local value.",
			Impact:     "Local value could be leaking secrets",
			Resolution: "Don't include sensitive data in locals",
			Explanation: `
Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.

*NOTE: It is also recommended to store your Terraform state in an encrypted form.*
`,
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
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},
		Provider:        provider.GeneralProvider,
		RequiredTypes:   []string{"locals"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			for _, attribute := range resourceBlock.GetAttributes() {
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.IsResolvable() {
						set.AddResult().WithDescription("Local '%s' includes a potentially sensitive value which is defined within the project.", resourceBlock.FullName()).
							WithAttribute(attribute)
					}
				}
			}

		},
	})
}
