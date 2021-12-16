package spaces

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "DIG006",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"digitalocean_spaces_bucket"},
		Base:           spaces.CheckVersioningEnabled,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("versioning") {
				results.Add("Resource does not have versioning block specified", resourceBlock)
				return
			}

			versioningBlock := resourceBlock.GetBlock("versioning")
			enabledAttr := versioningBlock.GetAttribute("enabled")

			if enabledAttr.IsNil() {
				results.Add("Resource has versioning specified, but it isn't enabled", resourceBlock)
			} else if enabledAttr.IsFalse() {
				results.Add("Resource has versioning specified, but it isn't enabled", enabledAttr)
			}

			return results
		},
	})
}
