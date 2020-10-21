package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// GenericSensitiveLocals See https://github.com/tfsec/tfsec#included-checks for check info
const GenericSensitiveLocals scanner.RuleCode = "GEN002"
const GenericSensitiveLocalsDescription scanner.RuleSummary = "Potentially sensitive data stored in local value."
const GenericSensitiveLocalsExplanation = `
Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.

*NOTE: It is also recommended to store your Terraform state in an encrypted form.*
`
const GenericSensitiveLocalsBadExample = `
locals {
  password = "p4ssw0rd"
}

resource "evil_corp" "virtual_machine" {
	root_password = local.password
}
`
const GenericSensitiveLocalsGoodExample = `
variable "password" {
  description = "The root password for our VM"
  type        = string
}

resource "evil_corp" "virtual_machine" {
	root_password = var.password
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GenericSensitiveLocals,
		Documentation: scanner.CheckDocumentation{
			Summary:     GenericSensitiveLocalsDescription,
			Explanation: GenericSensitiveLocalsExplanation,
			BadExample:  GenericSensitiveLocalsBadExample,
			GoodExample: GenericSensitiveLocalsGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},
		Provider:      scanner.GeneralProvider,
		RequiredTypes: []string{"locals"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var results []scanner.Result

			for _, attribute := range block.GetAttributes() {
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.Value().AsString() != "" {
						results = append(results, check.NewResultWithValueAnnotation(
							fmt.Sprintf("Local '%s' includes a potentially sensitive value which is defined within the project.", block.FullName()),
							attribute.Range(),
							attribute,
							scanner.SeverityWarning,
						))
					}
				}
			}

			return results
		},
	})
}
