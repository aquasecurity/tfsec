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

const DIGPublicReadAclOnSpacesBucket = "DIG005"
const DIGPublicReadAclOnSpacesBucketDescription = "Spaces bucket or bucket object has public read acl set"
const DIGPublicReadAclOnSpacesBucketImpact = "The contents of the space can be accessed publicly"
const DIGPublicReadAclOnSpacesBucketResolution = "Apply a more restrictive ACL"
const DIGPublicReadAclOnSpacesBucketExplanation = `
Space bucket and bucket object permissions should be set to deny public access unless explicitly required.
`
const DIGPublicReadAclOnSpacesBucketBadExample = `
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
`
const DIGPublicReadAclOnSpacesBucketGoodExample = `
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
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: DIGPublicReadAclOnSpacesBucket,
		Documentation: rule.RuleDocumentation{
			Summary:     DIGPublicReadAclOnSpacesBucketDescription,
			Explanation: DIGPublicReadAclOnSpacesBucketExplanation,
			Impact:      DIGPublicReadAclOnSpacesBucketImpact,
			Resolution:  DIGPublicReadAclOnSpacesBucketResolution,
			BadExample:  DIGPublicReadAclOnSpacesBucketBadExample,
			GoodExample: DIGPublicReadAclOnSpacesBucketGoodExample,
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
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.HasChild("acl") {
				aclAttr := resourceBlock.GetAttribute("acl")
				if aclAttr.Equals("public-read", block.IgnoreCase) {
					set.Add(result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has a publicly readable acl.", resourceBlock.FullName())).
						WithAttributeAnnotation(aclAttr).
						WithRange(aclAttr.Range()))
				}
			}
		},
	})
}
