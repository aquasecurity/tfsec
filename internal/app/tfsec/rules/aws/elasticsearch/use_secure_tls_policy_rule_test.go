package elasticsearch
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSOutdatedTLSPolicyElasticsearchDomainEndpoint(t *testing.T) {
 	expectedCode := "aws-elastic-search-use-secure-tls-policy"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check no domain_endpoint_options aws_elasticsearch_domain",
 			source: `
 resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
 	
 }`,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check tls_security_policy for aws_elasticsearch_domain isn't the default",
 			source: `
 resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
   }
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check tls_security_policy isn't set to TLsv1.0 for aws_elasticsearch_domain",
 			source: `
 resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
     tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
   }
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check tls_security_policy is set to TLSv1.2 for aws_elasticsearch_domain",
 			source: `
 resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
     tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
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
