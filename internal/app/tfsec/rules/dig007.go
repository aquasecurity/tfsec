package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const DIGForceDestroyEnabled = "DIG007"
const DIGForceDestroyEnabledDescription = "Force destroy is enabled on Spaces bucket which is dangerous"
const DIGForceDestroyEnabledImpact = "Accidental deletion of bucket objects"
const DIGForceDestroyEnabledResolution = "Don't use force destroy on bucket configuration"
const DIGForceDestroyEnabledExplanation = `
Enabling force destroy on a Spaces bucket means that the bucket can be deleted without the additional check that it is empty. This risks important data being accidentally deleted by a bucket removal process.
`
const DIGForceDestroyEnabledBadExample = `
resource "digitalocean_spaces_bucket" "bad_example" {
  name   		= "foobar"
  region 		= "nyc3"
  force_destroy = true
}
`
const DIGForceDestroyEnabledGoodExample = `
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: DIGForceDestroyEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     DIGForceDestroyEnabledDescription,
			Explanation: DIGForceDestroyEnabledExplanation,
			Impact:      DIGForceDestroyEnabledImpact,
			Resolution:  DIGForceDestroyEnabledResolution,
			BadExample:  DIGForceDestroyEnabledBadExample,
			GoodExample: DIGForceDestroyEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#force_destroy",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_spaces_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.HasChild("force_destroy") {
				forceDestroyAttr := resourceBlock.GetAttribute("force_destroy")
				if forceDestroyAttr.IsTrue() {
					set.Add(result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has versioning specified, but it isn't enabled", resourceBlock.FullName())).
						WithAttributeAnnotation(forceDestroyAttr).
						WithRange(forceDestroyAttr.Range()))
				}
			}
		},
	})
}
