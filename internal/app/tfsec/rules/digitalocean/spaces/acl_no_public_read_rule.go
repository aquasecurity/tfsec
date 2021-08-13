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
		LegacyID:  "DIG005",
		Service:   "spaces",
		ShortCode: "acl-no-public-read",
		Documentation: rule.RuleDocumentation{
			Summary: "Spaces bucket or bucket object has public read acl set",
			Explanation: `
Space bucket and bucket object permissions should be set to deny public access unless explicitly required.
`,
			Impact:     "The contents of the space can be accessed publicly",
			Resolution: "Apply a more restrictive ACL",
			BadExample: []string{`
resource "digitalocean_spaces_bucket" "bad_example" {
  name   = "public_space"
  region = "nyc3"
  acl    = "public-read"
}

resource "digitalocean_spaces_bucket_object" "index" {
  region       = digitalocean_spaces_bucket.bad_example.region
  bucket       = digitalocean_spaces_bucket.bad_example.name
  key          = "index.html"
  content      = "<html><body><p>This page is empty.</p></body></html>"
  content_type = "text/html"
  acl          = "public-read"
}
`},
			GoodExample: []string{`
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "private_space"
  region = "nyc3"
  acl    = "private"
}
  
resource "digitalocean_spaces_bucket_object" "index" {
  region       = digitalocean_spaces_bucket.good_example.region
  bucket       = digitalocean_spaces_bucket.good_example.name
  key          = "index.html"
  content      = "<html><body><p>This page is empty.</p></body></html>"
  content_type = "text/html"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#acl",
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket_object#acl",
				"https://docs.digitalocean.com/reference/api/spaces-api/#access-control-lists-acls",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_spaces_bucket", "digitalocean_spaces_bucket_object"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.HasChild("acl") {
				aclAttr := resourceBlock.GetAttribute("acl")
				if aclAttr.Equals("public-read", block.IgnoreCase) {
					set.AddResult().WithDescription("Resource '%s' has a publicly readable acl.", resourceBlock.FullName()).
						WithAttribute(aclAttr)
				}
			}
		},
	})
}
