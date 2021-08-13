package spaces

// generator-locked
import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "DIG007",
		Service:   "spaces",
		ShortCode: "disable-force-destroy",
		Documentation: rule.RuleDocumentation{
			Summary: "Force destroy is enabled on Spaces bucket which is dangerous",
			Explanation: `
Enabling force destroy on a Spaces bucket means that the bucket can be deleted without the additional check that it is empty. This risks important data being accidentally deleted by a bucket removal process.
`,
			Impact:     "Accidental deletion of bucket objects",
			Resolution: "Don't use force destroy on bucket configuration",
			BadExample: []string{`
resource "digitalocean_spaces_bucket" "bad_example" {
  name   		= "foobar"
  region 		= "nyc3"
  force_destroy = true
}
`},
			GoodExample: []string{`
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#force_destroy",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_spaces_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.HasChild("force_destroy") {
				forceDestroyAttr := resourceBlock.GetAttribute("force_destroy")
				if forceDestroyAttr.IsTrue() {
					set.AddResult().WithDescription("Resource '%s' has versioning specified, but it isn't enabled", resourceBlock.FullName()).
						WithAttribute(forceDestroyAttr)
				}
			}
		},
	})
}
