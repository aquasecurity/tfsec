package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSPlaintextNodeToNodeElasticsearchTraffic(t *testing.T) {
	expectedCode := "aws-elastic-search-enable-in-transit-encryption"

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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check true enabled attr aws_elasticsearch_domain",
			source: `
 resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
   domain_name = "domain-foo"
 
   node_to_node_encryption {
     enabled = "true"
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
