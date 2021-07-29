package spaces

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_DIGSpacesBucketVersioningEnabled(t *testing.T) {
	expectedCode := "digitalocean-spaces-versioning-enabled"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Spaces bucket with versioning left to default fails check",
			source: `
resource "digitalocean_spaces_bucket" "bad_example" {
  name   = "foobar"
  region = "nyc3"
}
`,
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
