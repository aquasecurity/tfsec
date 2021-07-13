package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const GENAttributeHasSensitiveData = "GEN005"
const GENAttributeHasSensitiveDataDescription = "The attribute has potentially sensitive data, passwords, tokens or keys in it"
const GENAttributeHasSensitiveDataImpact = "Sensitive credentials may be compromised"
const GENAttributeHasSensitiveDataResolution = "Check the code for vulnerabilities and move to variables"
const GENAttributeHasSensitiveDataExplanation = `
Sensitive data stored in attributes can result in compromised data. Sensitive data should be passed in through secret variables

`
const GENAttributeHasSensitiveDataBadExample = `
resource "aws_instance" "bad_example" {
	instance_type = "t2.small"

	user_data = <<EOF
		Password = "something secret"
EOF

}
`
const GENAttributeHasSensitiveDataGoodExample = `
variable "password" {
	type = string
}

resource "aws_instance" "good_instance" {
	instance_type = "t2.small"

	user_data = <<EOF
		Password = var.password
EOF

}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GENAttributeHasSensitiveData,
		Documentation: rule.RuleDocumentation{
			Summary:     GENAttributeHasSensitiveDataDescription,
			Explanation: GENAttributeHasSensitiveDataExplanation,
			Impact:      GENAttributeHasSensitiveDataImpact,
			Resolution:  GENAttributeHasSensitiveDataResolution,
			BadExample:  GENAttributeHasSensitiveDataBadExample,
			GoodExample: GENAttributeHasSensitiveDataGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},
		Provider:        provider.GeneralProvider,
		RequiredTypes:   []string{"resource", "provider", "module", "locals", "variable"},
		RequiredLabels:  []string{"*"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			attributes := resourceBlock.GetAttributes()

			for _, attribute := range attributes {
				if attribute.IsString() {
					if scanResult := security.StringScanner.Scan(attribute.Value().AsString()); scanResult.TransgressionFound {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Block '%s' includes potentially sensitive data. %s", resourceBlock.FullName(), scanResult.Description)).
								WithRange(attribute.Range()).
								WithAttributeAnnotation(attribute),
						)
					}
				}
			}
		},
	})
}
