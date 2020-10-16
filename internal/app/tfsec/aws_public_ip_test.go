package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSPublicIP(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_launch_configuration with public ip associated",
			source: `
resource "aws_launch_configuration" "my-resource" {
	associate_public_ip_address = true
}`,
			mustIncludeResultCode: aws.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance with public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = true
}`,
			mustIncludeResultCode: aws.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance without public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = false
}`,
			mustExcludeResultCode: aws.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance without public ip explicitly associated",
			source: `
resource "aws_instance" "my-resource" {
}`,
			mustExcludeResultCode: aws.AWSResourceHasPublicIP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
