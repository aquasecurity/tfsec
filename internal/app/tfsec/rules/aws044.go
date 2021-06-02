package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// AWSProviderHasAccessCredentials See https://github.com/tfsec/tfsec#included-checks for check info
const AWSProviderHasAccessCredentials = "AWS044"
const AWSProviderHasAccessCredentialsDescription = "AWS provider has access credentials specified."
const AWSProviderHasAccessCredentialsImpact = "Exposing the credentials in the Terraform provider increases the risk of secret leakage"
const AWSProviderHasAccessCredentialsResolution = "Don't include access credentials in plain text"
const AWSProviderHasAccessCredentialsExplanation = `
The AWS provider block should not contain hardcoded credentials. These can be passed in securely as runtime using environment variables.
`
const AWSProviderHasAccessCredentialsBadExample = `
provider "aws" {
  access_key = "AKIAABCD12ABCDEF1ABC"
  secret_key = "s8d7ghas9dghd9ophgs9"
}
`
const AWSProviderHasAccessCredentialsGoodExample = `
provider "aws" {
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSProviderHasAccessCredentials,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSProviderHasAccessCredentialsDescription,
			Impact:      AWSProviderHasAccessCredentialsImpact,
			Resolution:  AWSProviderHasAccessCredentialsResolution,
			Explanation: AWSProviderHasAccessCredentialsExplanation,
			BadExample:  AWSProviderHasAccessCredentialsBadExample,
			GoodExample: AWSProviderHasAccessCredentialsGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"provider"},
		RequiredLabels: []string{"aws"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if accessKeyAttribute := block.GetAttribute("access_key"); accessKeyAttribute != nil && accessKeyAttribute.Type() == cty.String {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Provider '%s' has an access key specified.", block.FullName()),
						accessKeyAttribute.Range(),
						accessKeyAttribute,
						severity.Error,
					),
				}
			} else if secretKeyAttribute := block.GetAttribute("secret_key"); secretKeyAttribute != nil && secretKeyAttribute.Type() == cty.String {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Provider '%s' has a secret key specified.", block.FullName()),
						secretKeyAttribute.Range(),
						secretKeyAttribute,
						severity.Error,
					),
				}
			}

			return nil
		},
	})
}
