package misc

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS044",
		Service:   "misc",
		ShortCode: "no-exposing-plaintext-credentials",
		Documentation: rule.RuleDocumentation{
			Summary:    "AWS provider has access credentials specified.",
			Impact:     "Exposing the credentials in the Terraform provider increases the risk of secret leakage",
			Resolution: "Don't include access credentials in plain text",
			Explanation: `
The AWS provider block should not contain hardcoded credentials. These can be passed in securely as runtime using environment variables.
`,
			BadExample: []string{`
provider "aws" {
  access_key = "AKIAABCD12ABCDEF1ABC"
  secret_key = "s8d7ghas9dghd9ophgs9"
}
`},
			GoodExample: []string{`
provider "aws" {
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs#argument-reference",
				"https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"provider"},
		RequiredLabels:  []string{"aws"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if accessKeyAttribute := resourceBlock.GetAttribute("access_key"); accessKeyAttribute.IsNotNil() && accessKeyAttribute.Type() == cty.String {
				set.AddResult().
					WithDescription("Provider '%s' has an access key specified.", resourceBlock.FullName()).
					WithAttribute(accessKeyAttribute)
			} else if secretKeyAttribute := resourceBlock.GetAttribute("secret_key"); secretKeyAttribute.IsNotNil() && secretKeyAttribute.Type() == cty.String {
				set.AddResult().
					WithDescription("Provider '%s' has a secret key specified.", resourceBlock.FullName()).
					WithAttribute(secretKeyAttribute)
			}

		},
	})
}
