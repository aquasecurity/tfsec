package rules

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const GenericSensitiveLocals = "GEN002"
const GenericSensitiveLocalsDescription = "Potentially sensitive data stored in local value."
const GenericSensitiveLocalsImpact = "Local value could be leaking secrets"
const GenericSensitiveLocalsResolution = "Don't include sensitive data in locals"
const GenericSensitiveLocalsExplanation = `
Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.

*NOTE: It is also recommended to store your Terraform state in an encrypted form.*
`
const GenericSensitiveLocalsBadExample = `
locals {
  password = "p4ssw0rd"
}

resource "evil_corp" "bad_example" {
	root_password = local.password
}
`
const GenericSensitiveLocalsGoodExample = `
variable "password" {
  description = "The root password for our VM"
  type        = string
}

resource "evil_corp" "good_example" {
	root_password = var.password
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GenericSensitiveLocals,
		Documentation: rule.RuleDocumentation{
			Summary:     GenericSensitiveLocalsDescription,
			Impact:      GenericSensitiveLocalsImpact,
			Resolution:  GenericSensitiveLocalsResolution,
			Explanation: GenericSensitiveLocalsExplanation,
			BadExample:  GenericSensitiveLocalsBadExample,
			GoodExample: GenericSensitiveLocalsGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},
		Provider:        provider.GeneralProvider,
		RequiredTypes:   []string{"locals"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			for _, attribute := range resourceBlock.GetAttributes() {
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.IsResolvable() {
						set.Add(result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Local '%s' includes a potentially sensitive value which is defined within the project.", resourceBlock.FullName())).
							WithRange(attribute.Range()).
							WithAttributeAnnotation(attribute),
						)
					}
				}
			}

		},
	})
}
