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

const DIGSpacesBucketVersioningEnabled = "DIG006"
const DIGSpacesBucketVersioningEnabledDescription = "Spaces buckets should have versioning enabled"
const DIGSpacesBucketVersioningEnabledImpact = "Deleted or modified data would not be recoverable"
const DIGSpacesBucketVersioningEnabledResolution = "Enable versioning to protect against accidental or malicious removal or modification"
const DIGSpacesBucketVersioningEnabledExplanation = `
Versioning is a means of keeping multiple variants of an object in the same bucket. You can use the Spaces (S3) Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. With versioning you can recover more easily from both unintended user actions and application failures.
`
const DIGSpacesBucketVersioningEnabledBadExample = `
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
`
const DIGSpacesBucketVersioningEnabledGoodExample = `
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"

  versioning {
	enabled = true
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: DIGSpacesBucketVersioningEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     DIGSpacesBucketVersioningEnabledDescription,
			Explanation: DIGSpacesBucketVersioningEnabledExplanation,
			Impact:      DIGSpacesBucketVersioningEnabledImpact,
			Resolution:  DIGSpacesBucketVersioningEnabledResolution,
			BadExample:  DIGSpacesBucketVersioningEnabledBadExample,
			GoodExample: DIGSpacesBucketVersioningEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#versioning",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_spaces_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("versioning") {
				set.Add(result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' does not have versioning enabled.", resourceBlock.FullName())).
					WithRange(resourceBlock.Range()))

				return
			}

			versioningBlock := resourceBlock.GetBlock("versioning")
			enabledAttr := versioningBlock.GetAttribute("enabled")

			if enabledAttr == nil || enabledAttr.IsFalse() {
				set.Add(result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' has versioning specified, but it isn't enabled", resourceBlock.FullName())).
					WithAttributeAnnotation(enabledAttr).
					WithRange(enabledAttr.Range()))

			}

		},
	})
}
