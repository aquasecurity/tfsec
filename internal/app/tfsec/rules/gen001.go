package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GenericSensitiveVariables See https://github.com/tfsec/tfsec#included-checks for check info
const GenericSensitiveVariables = "GEN001"
const GenericSensitiveVariablesDescription = "Potentially sensitive data stored in \"default\" value of variable."
const GenericSensitiveVariablesImpact = "Default values could be exposing sensitive data"
const GenericSensitiveVariablesResolution = "Don't include sensitive data in variable defaults"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: GenericSensitiveVariables,
		Documentation: rule.RuleDocumentation{
			Summary:     GenericSensitiveVariablesDescription,
			Impact:      GenericSensitiveVariablesImpact,
			Resolution:  GenericSensitiveVariablesResolution,
			Explanation: GenericSensitiveVariablesExplanation,
			BadExample:  GenericSensitiveVariablesBadExample,
			GoodExample: GenericSensitiveVariablesGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},
		Provider:      provider.GeneralProvider,
		RequiredTypes: []string{"variable"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if len(block.Labels()) == 0 {
			}

			if !security.IsSensitiveAttribute(block.TypeLabel()) {
			}

			for _, attribute := range block.GetAttributes() {
				if attribute.Name() == "default" {
					val := attribute.Value()
					if val.Type() != cty.String {
						continue
					}
					if val.AsString() != "" {
						set.Add(result.New().
							WithDescription(fmt.Sprintf("Variable '%s' includes a potentially sensitive default value.", block.FullName())).
							WithRange(attribute.Range()).
							WithAttributeAnnotation(attribute).
							WithSeverity(severity.Warning),
						)
					}
				}
			}

		},
	})
}
