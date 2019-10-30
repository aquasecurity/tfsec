package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSPlainHTTP(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check aws_alb_listener using plain HTTP",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTP"
}`,
			expectedResultCode: checks.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using plain HTTP (via non specification)",
			source: `
resource "aws_alb_listener" "my-listener" {
}`,
			expectedResultCode: checks.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using HTTPS",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTPS"
}`,
			expectedResultCode: checks.None,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCodeExists(t, test.expectedResultCode, results)
		})
	}

}
