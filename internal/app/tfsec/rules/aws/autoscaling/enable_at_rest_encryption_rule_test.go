package autoscaling

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSUnencryptedBlockDevice(t *testing.T) {
	expectedCode := "aws-autoscaling-enable-at-rest-encryption"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no root_block_device configured in launch configuration",
			source: `
 resource "aws_launch_configuration" "my-launch-config" {
 	
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check no encryption configured for ebs_block_device",
			source: `
 resource "aws_launch_configuration" "my-launch-config" {
 	root_block_device {}
 }`,
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check encryption disabled for root_block_device",
			source: `
 resource "aws_launch_configuration" "my-launch-config" {
 	root_block_device {
 		encrypted = false
 	}
 }`,
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check encryption enabled for root_block_device",
			source: `
 resource "aws_launch_configuration" "my-launch-config" {
 	root_block_device {
 		encrypted = true
 	}
 }`,
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check encryption enabled by default for non-specified root_block_device",
			source: `
 resource "aws_ebs_encryption_by_default" "example" {
   enabled = true
 }
 
 resource "aws_launch_configuration" "my-launch-config" {
 
 }`,
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
