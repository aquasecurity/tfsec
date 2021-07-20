package autoscaling

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSPublicIP(t *testing.T) {
	expectedCode := "aws-autoscaling-no-public-ip"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_instance with public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = true
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_instance without public ip associated",
			source: `
resource "aws_instance" "my-resource" {
	associate_public_ip_address = false
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check aws_instance without public ip explicitly associated",
			source: `
resource "aws_instance" "my-resource" {
}`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
