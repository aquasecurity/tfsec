package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSUnencryptedBlockDevice(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check no ebs_block_device configured in launch configuration",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	
}`,
			expectedResultCode: checks.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check no encryption configured for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device = {}
}`,
			expectedResultCode: checks.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption disabled for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device = {
		encrypted = false
	}
}`,
			expectedResultCode: checks.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device = {
		encrypted = true
	}
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
