package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSElasticSearchDataStoreEncryptedAtRest(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check fails when encyrtion at rest not defined",
			source: `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"
}
`,
			mustIncludeResultCode: checks.AWSElasticSearchDataStoreEncryptedAtRest,
		},
		{
			name: "check fails when encryption at rest defined but disabled",
			source: `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
    enabled = false
  }
}
`,
			mustIncludeResultCode: checks.AWSElasticSearchDataStoreEncryptedAtRest,
		},
		{
			name: "check passes when encryption at rest defined and enabled",
			source: `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
    enabled = true
  }
}
`,
			mustExcludeResultCode: checks.AWSElasticSearchDataStoreEncryptedAtRest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
