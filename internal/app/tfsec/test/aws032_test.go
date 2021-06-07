package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSPlaintextNodeToNodeElasticsearchTraffic(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no node_to_node_encryption block aws_elasticsearch_domain",
			source: `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
	
}`,
			mustIncludeResultCode: rules.AWSPlaintextNodeToNodeElasticsearchTraffic,
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
			mustIncludeResultCode: rules.AWSPlaintextNodeToNodeElasticsearchTraffic,
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
			mustExcludeResultCode: rules.AWSPlaintextNodeToNodeElasticsearchTraffic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
