package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSPlainHTTP(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_alb_listener using plain HTTP",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTP"
}`,
			mustIncludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_lb_listener using plain HTTP",
			source: `
resource "aws_lb_listener" "my-listener" {
	protocol = "HTTP"
}`,
			mustIncludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using plain HTTP (via non specification)",
			source: `
resource "aws_alb_listener" "my-listener" {
}`,
			mustIncludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using HTTPS",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTPS"
}`,
			mustExcludeResultCode: rules.AWSPlainHTTP,
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
			mustExcludeResultCode: rules.AWSPlainHTTP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
