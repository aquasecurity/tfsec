package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSAWSESDomainShouldHaveAuditLogEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Test if log_type is missing throw an error",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
  }
}
`,
			mustIncludeResultCode: checks.AWSESDomainLoggingEnabled,
		},
		{
			name: "Test if log_publishing_options missing throw an error",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config
}
`,
			mustIncludeResultCode: checks.AWSESDomainLoggingEnabled,
		},
		{
			name: "Test if log_type missing AUDIT_LOGS throw an error",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "SEARCH_SLOW_LOGS,ES_APPLICATION_LOGS"
  }
}
`,
			mustIncludeResultCode: checks.AWSESDomainLoggingEnabled,
		},
		{
			name: "Test check passes if conditions are met",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
}
`,
			mustExcludeResultCode: checks.AWSESDomainLoggingEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
