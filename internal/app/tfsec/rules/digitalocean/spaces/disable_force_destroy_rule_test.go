package spaces

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_DIGForceDestroyEnabled(t *testing.T) {
	expectedCode := "digitalocean-spaces-disable-force-destroy"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "force destroy turned on fails check",
			source: `
resource "digitalocean_spaces_bucket" "bad_example" {
  name   		= "foobar"
  region 		= "nyc3"
  force_destroy = true
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "force destroy left to default passes check",
			source: `
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "force destroy explicitly turned off passes check",
			source: `
resource "digitalocean_spaces_bucket" "good_example" {
	name   	 	  = "foobar"
	region 		  = "nyc3"
	force_destroy = false
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
