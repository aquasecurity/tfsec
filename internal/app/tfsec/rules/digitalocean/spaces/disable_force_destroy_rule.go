package spaces

import (
	"github.com/aquasecurity/defsec/rules/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "DIG007",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"digitalocean_spaces_bucket"},
		Base:           spaces.CheckDisableForceDestroy,
	})
}
