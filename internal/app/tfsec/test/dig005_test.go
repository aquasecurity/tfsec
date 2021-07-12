package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_DIGPublicReadAclOnSpacesBucket(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Spaces bucket with public-read acl fails check",
			source: `
resource "digitalocean_spaces_bucket" "bad_example" {
  name   = "public_space"
  region = "nyc3"
  acl    = "public-read"
}
`,
			mustIncludeResultCode: rules.DIGPublicReadAclOnSpacesBucket,
		},
		{
			name: "Spaces bucket object with public-read acl fails check",
			source: `
resource "digitalocean_spaces_bucket_object" "index" {
  region       = digitalocean_spaces_bucket.bad_example.region
  bucket       = digitalocean_spaces_bucket.bad_example.name
  key          = "index.html"
  content      = "<html><body><p>This page is empty.</p></body></html>"
  content_type = "text/html"
  acl          = "public-read"
}
`,
			mustIncludeResultCode: rules.DIGPublicReadAclOnSpacesBucket,
		},
		{
			name: "Spaces bucket object using default acl (private) passes check",
			source: `
resource "digitalocean_spaces_bucket_object" "index" {
  region       = digitalocean_spaces_bucket.good_example.region
  bucket       = digitalocean_spaces_bucket.good_example.name
  key          = "index.html"
  content      = "<html><body><p>This page is empty.</p></body></html>"
  content_type = "text/html"
}
`,
			mustExcludeResultCode: rules.DIGPublicReadAclOnSpacesBucket,
		},
		{
			name: "Spaces bucket using explicit private acl passes check",
			source: `
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "private_space"
  region = "nyc3"
  acl    = "private"
}
`,
			mustExcludeResultCode: rules.DIGPublicReadAclOnSpacesBucket,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
