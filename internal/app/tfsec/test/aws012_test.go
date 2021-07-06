package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSPublicIP(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_launch_configuration with public ip associated",
			source: `
resource "aws_launch_configuration" "my-resource" {
	associate_public_ip_address = true
}`,
			mustIncludeResultCode: rules.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance with public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = true
}`,
			mustIncludeResultCode: rules.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance without public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = false
}`,
			mustExcludeResultCode: rules.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance without public ip explicitly associated",
			source: `
resource "aws_instance" "my-resource" {
}`,
			mustExcludeResultCode: rules.AWSResourceHasPublicIP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
