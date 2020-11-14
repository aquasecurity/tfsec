package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSElasticSearchDomainEnforceHTTPS(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check enforce_https false fails check",
			source: `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }
}
`,
			mustIncludeResultCode: checks.AWSElasticSearchDomainEnforceHTTPS,
		},
		{
			name: "check passes when enforce_https is true",
			source: `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

domain_endpoint_options {
    enforce_https = true
  }
}
`,
			mustExcludeResultCode: checks.AWSElasticSearchDomainEnforceHTTPS,
		},
		{
			name: "check passes when domain_endpoint_options is blank",
			source: `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

}
`,
			mustExcludeResultCode: checks.AWSElasticSearchDomainEnforceHTTPS,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
