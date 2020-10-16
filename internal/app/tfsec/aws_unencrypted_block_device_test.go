package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSUnencryptedBlockDevice(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check no root_block_device configured in launch configuration",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	
}`,
			mustIncludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check no encryption configured for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {}
}`,
			mustIncludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check no encryption configured for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {
		encrypted = true
	}
	ebs_block_device {}
}`,
			mustIncludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption disabled for root_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {
		encrypted = false
	}
}`,
			mustIncludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption disabled for ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {
		encrypted = true
	}
	ebs_block_device {
		encrypted = false
	}
}`,
			mustIncludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled for root_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {
		encrypted = true
	}
}`,
			mustExcludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled for root_block_device and ebs_block_device",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {
		encrypted = true
	}
	ebs_block_device {
		encrypted = true
	}
}`,
			mustExcludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled by default for root_block_device",
			source: `
resource "aws_ebs_encryption_by_default" "example" {
  enabled = true
}

resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {

	}
}`,
			mustExcludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled by default for non-specified root_block_device",
			source: `
resource "aws_ebs_encryption_by_default" "example" {
  enabled = true
}

resource "aws_launch_configuration" "my-launch-config" {

}`,
			mustExcludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled by default for non-specified root_block_device and ebs_block_device",
			source: `
resource "aws_ebs_encryption_by_default" "example" {
  enabled = true
}

resource "aws_launch_configuration" "my-launch-config" {
	ebs_block_device{}
}`,
			mustExcludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
		{
			name: "check encryption enabled for one ebs_block_device and not for another",
			source: `
resource "aws_launch_configuration" "my-launch-config" {
	root_block_device {
		encrypted = true
	}
	ebs_block_device{
		encrypted  = true
	}
	ebs_block_device{
		encrypted  = false
	}
}`,
			mustIncludeResultCode: aws.AWSLaunchConfigurationWithUnencryptedBlockDevice,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
