package secrets

// generator-locked
import (
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
		LegacyID:  "GEN005",
		Service:   "secrets",
		ShortCode: "sensitive-in-attribute-value",
		Documentation: rule.RuleDocumentation{
			Summary: "The attribute has potentially sensitive data, passwords, tokens or keys in it",
			Explanation: `
Sensitive data stored in attributes can result in compromised data. Sensitive data should be passed in through secret variables

`,
			Impact:     "Sensitive credentials may be compromised",
			Resolution: "Check the code for vulnerabilities and move to variables",
			BadExample: []string{`
resource "aws_instance" "bad_example" {
	instance_type = "t2.small"

	user_data = <<EOF
		Password = "something secret"
EOF

}
`},
			GoodExample: []string{`
variable "password" {
	type = string
}

resource "aws_instance" "good_instance" {
	instance_type = "t2.small"

	user_data = <<EOF
		export EDITOR=vimacs
EOF

}
`},
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
		},

		Provider:        provider.GeneralProvider,
		RequiredTypes:   []string{"resource", "provider", "module", "locals", "variable"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			attributes := resourceBlock.GetAttributes()

			for _, attribute := range attributes {
				if attribute.IsString() {
					if scanResult := security.StringScanner.Scan(attribute.Value().AsString()); scanResult.TransgressionFound {
						set.AddResult().
							WithDescription("Block '%s' includes potentially sensitive data. %s", resourceBlock.FullName(), scanResult.Description).
							WithAttribute(attribute)
					}
				}
			}
		},
	})
}
