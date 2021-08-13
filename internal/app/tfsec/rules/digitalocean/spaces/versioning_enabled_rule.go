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
		LegacyID:  "DIG006",
		Service:   "spaces",
		ShortCode: "versioning-enabled",
		Documentation: rule.RuleDocumentation{
			Summary: "Spaces buckets should have versioning enabled",
			Explanation: `
Versioning is a means of keeping multiple variants of an object in the same bucket. You can use the Spaces (S3) Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. With versioning you can recover more easily from both unintended user actions and application failures.
`,
			Impact:     "Deleted or modified data would not be recoverable",
			Resolution: "Enable versioning to protect against accidental or malicious removal or modification",
			BadExample: []string{`
resource "digitalocean_spaces_bucket" "bad_example" {
  name   = "foobar"
  region = "nyc3"
}

resource "digitalocean_spaces_bucket" "bad_example" {
  name   = "foobar"
  region = "nyc3"

  versioning {
	enabled = false	
  }
}
`},
			GoodExample: []string{`
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"

  versioning {
	enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#versioning",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_spaces_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("versioning") {
				set.AddResult().WithDescription("Resource '%s' does not have versioning block specified", resourceBlock.FullName())
				return
			}

			versioningBlock := resourceBlock.GetBlock("versioning")
			enabledAttr := versioningBlock.GetAttribute("enabled")

			if enabledAttr.IsNil() || enabledAttr.IsFalse() {
				set.AddResult().WithDescription("Resource '%s' has versioning specified, but it isn't enabled", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}

		},
	})
}
