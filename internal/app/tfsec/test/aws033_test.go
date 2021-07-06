package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnenforcedHTTPSElasticsearchDomainEndpoint(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no  domain_endpoint_options aws_elasticsearch_domain",
			source: `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
	
}`,
			mustIncludeResultCode: rules.AWSUnenforcedHTTPSElasticsearchDomainEndpoint,
		},
		{
			name: "check false enforce_https attr aws_elasticsearch_domain",
			source: `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = false
  }
}`,
			mustIncludeResultCode: rules.AWSUnenforcedHTTPSElasticsearchDomainEndpoint,
		},
		{
			name: "check true enforce_https aws_elasticsearch_domain",
			source: `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = true
  }
}`,
			mustExcludeResultCode: rules.AWSUnenforcedHTTPSElasticsearchDomainEndpoint,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
