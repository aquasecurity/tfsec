package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSPublicIP(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check aws_launch_configuration with public ip associated",
			source: `
resource "aws_launch_configuration" "my-resource" {
	associate_public_ip_address = true
}`,
			expectsResults: true,
		},
		{
			name: "check aws_instance with public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = true
}`,
			expectsResults: true,
		},
		{
			name: "check aws_instance without public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = false
}`,
			expectsResults: false,
		},
		{
			name: "check aws_instance without public ip explicitly associated",
			source: `
resource "aws_instance" "my-resource" {
}`,
			expectsResults: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assert.Equal(t, test.expectsResults, len(results) > 0)
		})
	}

}
