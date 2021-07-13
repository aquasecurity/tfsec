package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"provider"},
		RequiredLabels:  []string{"aws"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if accessKeyAttribute := resourceBlock.GetAttribute("access_key"); accessKeyAttribute != nil && accessKeyAttribute.Type() == cty.String {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Provider '%s' has an access key specified.", resourceBlock.FullName())).
						WithRange(accessKeyAttribute.Range()).
						WithAttributeAnnotation(accessKeyAttribute),
				)
			} else if secretKeyAttribute := resourceBlock.GetAttribute("secret_key"); secretKeyAttribute != nil && secretKeyAttribute.Type() == cty.String {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Provider '%s' has a secret key specified.", resourceBlock.FullName())).
						WithRange(secretKeyAttribute.Range()).
						WithAttributeAnnotation(secretKeyAttribute),
				)
			}

		},
	})
}
