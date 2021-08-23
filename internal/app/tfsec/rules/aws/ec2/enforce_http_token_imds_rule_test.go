package ec2

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSInstanceMetadataChec(t *testing.T) {
	expectedCode := "aws-ec2-enforce-http-token-imds"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "should fire as http_tokens not specified and by default are optional",
			source: `
		resource "aws_instance" "working example"{
		ami           = "ami-005e54dee72cc1d00"
		instance_type = "t2.micro"
		}
		`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "should fire as http_tokens explicitly set to optional and should be required",
			source: `
		resource "aws_instance" "working example"{
		ami           = "ami-005e54dee72cc1d00"
		instance_type = "t2.micro"
		metadata_options {
		http_tokens = "optional"
		}
		}
		`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "should not fire when http_tokens set to required",
			source: `
		 resource "aws_instance" "working example"{
			 ami           = "ami-005e54dee72cc1d00"
			 instance_type = "t2.micro"
			 metadata_options {
			 http_tokens = "required"
			 }
		 }
		 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "should not fire when http_endpoint disabled as IMDS is not available",
			source: `
 resource "aws_instance" "working example"{
	 ami           = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
	 metadata_options {
	 http_endpoint = "disabled"
	 http_tokens   = "optional"
	 }	
 }
 `,
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
