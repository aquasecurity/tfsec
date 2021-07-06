package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSOutdatedSSLPolicy(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_alb_listener with outdated policy",
			source: `
resource "aws_alb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
	protocol = "HTTPS"
}`,
			mustIncludeResultCode: rules.AWSOutdatedSSLPolicy,
		},
		{
			name: "check aws_lb_listener with outdated policy",
			source: `
resource "aws_lb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
	protocol = "HTTPS"
}`,
			mustIncludeResultCode: rules.AWSOutdatedSSLPolicy,
		},
		{
			name: "check aws_alb_listener with ok policy",
			source: `
resource "aws_alb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
	protocol = "HTTPS"
}`,
			mustExcludeResultCode: rules.AWSOutdatedSSLPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
