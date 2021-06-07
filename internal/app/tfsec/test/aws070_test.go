package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSAWSESDomainShouldHaveAuditLogEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check fails if any of the log options dont specify log_type of AUDIT_LOGS",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "TEST_LOGS"
  }
}
`,
			mustIncludeResultCode: rules.AWSESDomainLoggingEnabled,
		},
		{
			name: "check passes if one of the log_type is AUDIT_LOGS and audit log is enabled",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
}
`,
			mustExcludeResultCode: rules.AWSESDomainLoggingEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
