package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// GenericSensitiveAttributes See https://github.com/tfsec/tfsec#included-checks for check info
const GenericSensitiveAttributes scanner.RuleCode = "GEN003"
const GenericSensitiveAttributesDescription scanner.RuleSummary = "Potentially sensitive data stored in block attribute."
const GenericSensitiveAttributesExplanation = `
Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.

*NOTE: It is also recommended to store your Terraform state in an encrypted form.*
`
const GenericSensitiveAttributesBadExample = `
resource "evil_corp" "virtual_machine" {
	root_password = "p4ssw0rd"
}
`
const GenericSensitiveAttributesGoodExample = `
variable "password" {
  description = "The root password for our VM"
  type        = string
}

resource "evil_corp" "virtual_machine" {
	root_password = var.password
}
`

var sensitiveWhitelist = []struct {
	Resource  string
	Attribute string
}{
	{
		Resource:  "aws_efs_file_system",
		Attribute: "creation_token",
	},
	{
		Resource:  "aws_instance",
		Attribute: "get_password_data",
	},
}

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GenericSensitiveAttributes,
		Documentation: scanner.CheckDocumentation{
			Summary:     GenericSensitiveAttributesDescription,
			Explanation: GenericSensitiveAttributesExplanation,
			BadExample:  GenericSensitiveAttributesBadExample,
			GoodExample: GenericSensitiveAttributesGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},
		Provider:      scanner.GeneralProvider,
		RequiredTypes: []string{"resource", "provider", "module"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			attributes := block.GetAttributes()

			var results []scanner.Result
		SKIP:
			for _, attribute := range attributes {
				for _, whitelisted := range sensitiveWhitelist {
					if whitelisted.Resource == block.TypeLabel() && whitelisted.Attribute == attribute.Name() {
						continue SKIP
					}
				}
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.Value().AsString() != "" {
						results = append(results, check.NewResultWithValueAnnotation(
							fmt.Sprintf("Block '%s' includes a potentially sensitive attribute which is defined within the project.", block.FullName()),
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
