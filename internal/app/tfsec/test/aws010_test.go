package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSOutdatedSSLPolicy(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_alb_listener with outdated policy",
			source: `
resource "aws_alb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
	protocol = "HTTPS"
}`,
			mustIncludeResultCode: checks.AWSOutdatedSSLPolicy,
		},
		{
			name: "check aws_lb_listener with outdated policy",
			source: `
resource "aws_lb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
	protocol = "HTTPS"
}`,
			mustIncludeResultCode: checks.AWSOutdatedSSLPolicy,
		},
		{
			name: "check aws_alb_listener with ok policy",
			source: `
resource "aws_alb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
	protocol = "HTTPS"
}`,
			mustExcludeResultCode: checks.AWSOutdatedSSLPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
