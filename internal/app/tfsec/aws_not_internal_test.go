package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSNotInternal(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_alb when not internal",
			source: `
resource "aws_alb" "my-resource" {
	internal = false
}`,
			mustIncludeResultCode: aws.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_elb when not internal",
			source: `
resource "aws_elb" "my-resource" {
	internal = false
}`,
			mustIncludeResultCode: aws.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_lb when not internal",
			source: `
resource "aws_lb" "my-resource" {
	internal = false
}`,
			mustIncludeResultCode: aws.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_lb when not explicitly marked as internal",
			source: `
resource "aws_lb" "my-resource" {
}`,
			mustIncludeResultCode: aws.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_lb when explicitly marked as internal",
			source: `
resource "aws_lb" "my-resource" {
	internal = true
}`,
			mustExcludeResultCode: aws.AWSExternallyExposedLoadBalancer,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
