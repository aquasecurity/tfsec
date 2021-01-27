package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// GenericSensitiveVariables See https://github.com/tfsec/tfsec#included-checks for check info
const GenericSensitiveVariables scanner.RuleCode = "GEN001"
const GenericSensitiveVariablesDescription scanner.RuleSummary = "Potentially sensitive data stored in \"default\" value of variable."
const GenericSensitiveVariablesExplanation = `
Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.

*NOTE: It is also recommended to store your Terraform state in an encrypted form.*
`
const GenericSensitiveVariablesBadExample = `
variable "password" {
  description = "The root password for our VM"
  type        = string
  default     = "p4ssw0rd"
}

resource "evil_corp" "virtual_machine" {
	root_password = var.password
}
`
const GenericSensitiveVariablesGoodExample = `
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
		Code: GenericSensitiveVariables,
		Documentation: scanner.CheckDocumentation{
			Summary:     GenericSensitiveVariablesDescription,
			Explanation: GenericSensitiveVariablesExplanation,
			BadExample:  GenericSensitiveVariablesBadExample,
			GoodExample: GenericSensitiveVariablesGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},
		Provider:      scanner.GeneralProvider,
		RequiredTypes: []string{"variable"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if len(block.Labels()) == 0 {
				return nil
			}

			if !security.IsSensitiveAttribute(block.TypeLabel()) {
				return nil
			}

			var results []scanner.Result

			for _, attribute := range block.GetAttributes() {
				if attribute.Name() == "default" {
					val := attribute.Value()
					if val.Type() != cty.String {
						continue
					}
					if val.AsString() != "" {
						results = append(results, check.NewResultWithValueAnnotation(
							fmt.Sprintf("Variable '%s' includes a potentially sensitive default value.", block.FullName()),
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
