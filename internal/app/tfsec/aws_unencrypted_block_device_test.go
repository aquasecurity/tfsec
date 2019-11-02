package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSUnencryptedBlockDevice(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.Code
		mustExcludeResultCode scanner.Code
	}{
		{
			name: "check no ebs_block_device configured in launch configuration",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	
}`,
			mustIncludeResultCode: checks.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check no encryption configured for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device {}
}`,
			mustIncludeResultCode: checks.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption disabled for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device {
		encrypted = false
	}
}`,
			mustIncludeResultCode: checks.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device {
		encrypted = true
	}
}`,
			mustExcludeResultCode: checks.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
