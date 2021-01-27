package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSProviderHasAccessCredentials See https://github.com/tfsec/tfsec#included-checks for check info
const AWSProviderHasAccessCredentials scanner.RuleCode = "AWS044"
const AWSProviderHasAccessCredentialsDescription scanner.RuleSummary = "AWS provider has access credentials specified."
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSProviderHasAccessCredentials,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSProviderHasAccessCredentialsDescription,
			Explanation: AWSProviderHasAccessCredentialsExplanation,
			BadExample:  AWSProviderHasAccessCredentialsBadExample,
			GoodExample: AWSProviderHasAccessCredentialsGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"provider"},
		RequiredLabels: []string{"aws"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if accessKeyAttribute := block.GetAttribute("access_key"); accessKeyAttribute != nil && accessKeyAttribute.Type() == cty.String {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Provider '%s' has an access key specified.", block.FullName()),
						accessKeyAttribute.Range(),
						accessKeyAttribute,
						scanner.SeverityError,
					),
				}
			} else if secretKeyAttribute := block.GetAttribute("secret_key"); secretKeyAttribute != nil && secretKeyAttribute.Type() == cty.String {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Provider '%s' has a secret key specified.", block.FullName()),
						secretKeyAttribute.Range(),
						secretKeyAttribute,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
