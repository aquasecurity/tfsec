package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_DIGSpacesBucketVersioningEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Spaces bucket with versioning actively disabled fails check",
			source: `
resource "digitalocean_spaces_bucket" "bad_example" {
  name   = "foobar"
  region = "nyc3"

  versioning {
	enabled = false	
  }
}
`,
			mustIncludeResultCode: rules.DIGSpacesBucketVersioningEnabled,
		},
		{
			name: "Spaces bucket with versioning left to default fails check",
			source: `
resource "digitalocean_spaces_bucket" "bad_example" {
  name   = "foobar"
  region = "nyc3"
}
`,
			mustIncludeResultCode: rules.DIGSpacesBucketVersioningEnabled,
		},
		{
			name: "Spaces bucket with versioning enabled passes check",
			source: `
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"

  versioning {
	enabled = true
  }
}
`,
			mustExcludeResultCode: rules.DIGSpacesBucketVersioningEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
