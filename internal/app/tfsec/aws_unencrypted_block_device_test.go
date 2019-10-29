package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSUnencryptedBlockDevice(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check no ebs_block_device configured in launch configuration",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	
}`,
			expectsResults: true,
		},
		{
			name: "check no encryption configured for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device = {}
}`,
			expectsResults: true,
		},
		{
			name: "check encryption disabled for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device = {
		encrypted = false
	}
}`,
			expectsResults: true,
		},
		{
			name: "check encryption enabled for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device = {
		encrypted = true
	}
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
