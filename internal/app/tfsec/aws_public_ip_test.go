package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSPublicIP(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check aws_launch_configuration with public ip associated",
			source: `
resource "aws_launch_configuration" "my-resource" {
	associate_public_ip_address = true
}`,
			expectedResultCode: checks.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance with public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = true
}`,
			expectedResultCode: checks.AWSResourceHasPublicIP,
		},
		{
			name: "check aws_instance without public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = false
}`,
			expectedResultCode: checks.None,
		},
		{
			name: "check aws_instance without public ip explicitly associated",
			source: `
resource "aws_instance" "my-resource" {
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
