package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSInstanceMetadataChec(t *testing.T) {

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
			mustIncludeResultCode: rules.AWSInstanceMetadataChec,
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
			mustIncludeResultCode: rules.AWSInstanceMetadataChec,
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
			mustExcludeResultCode: rules.AWSInstanceMetadataChec,
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
			mustExcludeResultCode: rules.AWSInstanceMetadataChec,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
