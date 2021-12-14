package elasticsearch
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSElasticSearchHasDomainLogging(t *testing.T) {
 	expectedCode := "aws-elastic-search-enable-domain-logging"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check fails when the logging block is missing",
 			source: `
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check fails when the log options are present but disabled",
 			source: `
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "INDEX_SLOW_LOGS"
     enabled                  = false  
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check passes when the log options are present and enabled not specified",
 			source: `
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "INDEX_SLOW_LOGS"
   }
 }
 `,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check passes when the log options are present and explicitly enabled",
 			source: `
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "INDEX_SLOW_LOGS"
     enabled                  = true  
   }
 }
 `,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check fails when one of the log options are present but disabled",
 			source: `
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "INDEX_SLOW_LOGS"
     enabled                  = true
   }
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "AUDIT_LOGS"
     enabled                  = false
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 	}
 
 	for _, test := range tests {
 		t.Run(test.name, func(t *testing.T) {
 
 			results := testutil.ScanHCL(test.source, t)
 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
 		})
 	}
 
 }
