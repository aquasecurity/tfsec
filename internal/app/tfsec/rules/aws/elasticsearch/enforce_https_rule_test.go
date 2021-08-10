package elasticsearch

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSUnenforcedHTTPSElasticsearchDomainEndpoint(t *testing.T) {
	expectedCode := "aws-elastic-search-enforce-https"

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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
