package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSPlainHTTP(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_alb_listener using plain HTTP",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTP"
}`,
			mustIncludeResultCode: checks.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using plain HTTP (via non specification)",
			source: `
resource "aws_alb_listener" "my-listener" {
}`,
			mustIncludeResultCode: checks.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using HTTPS",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTPS"
}`,
			mustExcludeResultCode: checks.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using HTTP as redirect to HTTPS",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTP"
	default_action {
		type = "redirect"

		redirect {
			port        = "443"
			protocol    = "HTTPS"
			status_code = "HTTP_301"
		}
	}
}`,
			mustExcludeResultCode: checks.AWSPlainHTTP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
