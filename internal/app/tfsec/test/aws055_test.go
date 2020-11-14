package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSElasticSearchNodeToNodeEncryption(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check when node_to_node_encryption block not defined the check fails",
			source: `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }
}
`,
			mustIncludeResultCode: checks.AWSElasticSearchNodeToNodeEncryption,
		},
		{
			name: "check fails when node_to_node_encrytion is disabled",
			source: `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }

  node_to_node_encryption {
    enabled = false
  }
}
`,
			mustIncludeResultCode: checks.AWSElasticSearchNodeToNodeEncryption,
		},
		{
			name: "check passes when node_to_node_encryption is enabled",
			source: `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }

  node_to_node_encryption {
    enabled = true
  }
}
`,
			mustExcludeResultCode: checks.AWSElasticSearchNodeToNodeEncryption,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
