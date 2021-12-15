package misc

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/general/secrets"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS044",
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
		RequiredTypes:  []string{"provider"},
		RequiredLabels: []string{"aws"},
		Base:           secrets.CheckNotExposed,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if accessKeyAttribute := resourceBlock.GetAttribute("access_key"); accessKeyAttribute.IsNotNil() && accessKeyAttribute.Type() == cty.String {
				results.Add("Provider '%s' has an access key specified.", accessKeyAttribute)
			} else if secretKeyAttribute := resourceBlock.GetAttribute("secret_key"); secretKeyAttribute.IsNotNil() && secretKeyAttribute.Type() == cty.String {
				results.Add("Provider '%s' has a secret key specified.", secretKeyAttribute)
			}

			return results
		},
	})
}
