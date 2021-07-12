package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_DIGForceDestroyEnabled(t *testing.T) {

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
			mustIncludeResultCode: rules.DIGForceDestroyEnabled,
		},
		{
			name: "force destroy left to default passes check",
			source: `
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"
}
`,
			mustExcludeResultCode: rules.DIGForceDestroyEnabled,
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
			mustExcludeResultCode: rules.DIGForceDestroyEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
