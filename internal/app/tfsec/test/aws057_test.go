package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSElasticSearchHasDomainLogging(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check fails when the logging block is missing",
			source: `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"
}
`,
			mustIncludeResultCode: checks.AWSElasticSearchHasDomainLogging,
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
			mustIncludeResultCode: checks.AWSElasticSearchHasDomainLogging,
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
			mustExcludeResultCode: checks.AWSElasticSearchHasDomainLogging,
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
			mustExcludeResultCode: checks.AWSElasticSearchHasDomainLogging,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
