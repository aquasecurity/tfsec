package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSPlaintextNodeToNodeElasticsearchTraffic(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check no node_to_node_encryption block aws_elasticsearch_domain",
			source: `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
	
}`,
			mustIncludeResultCode: checks.AWSPlaintextNodeToNodeElasticsearchTraffic,
		},
		{
			name: "check false enabled attr aws_elasticsearch_domain",
			source: `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = false
  }
}`,
			mustIncludeResultCode: checks.AWSPlaintextNodeToNodeElasticsearchTraffic,
		},
		{
			name: "check true enabled attr aws_elasticsearch_domain",
			source: `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = true
  }
}`,
			mustExcludeResultCode: checks.AWSPlaintextNodeToNodeElasticsearchTraffic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
