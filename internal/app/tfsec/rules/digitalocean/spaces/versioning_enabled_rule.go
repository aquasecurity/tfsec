package spaces

import (
	"github.com/aquasecurity/defsec/rules/digitalocean/spaces"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"digitalocean_spaces_bucket"},
		Base:           spaces.CheckVersioningEnabled,
	})
}
