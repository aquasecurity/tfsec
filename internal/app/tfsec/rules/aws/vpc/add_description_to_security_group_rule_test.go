package vpc

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSMissingDescriptionForSecurityGroup(t *testing.T) {
	expectedCode := "aws-vpc-add-description-to-security-group"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_security_group without description",
			source: `
resource "aws_security_group" "my-group" {
	
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group_rule without description",
			source: `
resource "aws_security_group_rule" "my-rule" {
	
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group with description",
			source: `
resource "aws_security_group" "my-group" {
	description = "this is a group for allowing shiz"
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group_rule with description",
			source: `
resource "aws_security_group_rule" "my-rule" {
	description = "this is a group for allowing shiz"
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "ingress block entry with no description has error",
			source: `
			resource "aws_security_group" "bad_example" {
				name        = "http"
				description = "some description"
			  
				ingress  {
					description = "ingress block description"
					from_port   = 80
					to_port     = 80
					protocol    = "tcp"
					cidr_blocks = [aws_vpc.main.cidr_block]
				  }

				ingress  {
					  from_port   = 80
					  to_port     = 80
					  protocol    = "tcp"
					  cidr_blocks = [aws_vpc.main.cidr_block]
					}
			  }
			  `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "ingress block entry with description has no error",
			source: `
			resource "aws_security_group" "bad_example" {
				name        = "http"
				description = "some description"
			  
				ingress  {
					  description = "ingress block description"
					  from_port   = 80
					  to_port     = 80
					  protocol    = "tcp"
					  cidr_blocks = [aws_vpc.main.cidr_block]
					}
			  }
			  `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "egress block entry with no description has error",
			source: `
			resource "aws_security_group" "bad_example" {
				name        = "http"
				description = "some description"
			  
				egress  {
					description = "ingress block description"
					from_port   = 80
					to_port     = 80
					protocol    = "tcp"
					cidr_blocks = [aws_vpc.main.cidr_block]
				  }

				  egress  {
					  from_port   = 80
					  to_port     = 80
					  protocol    = "tcp"
					  cidr_blocks = [aws_vpc.main.cidr_block]
					}
			  }
			  `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "egress block entry with description has no error",
			source: `
			resource "aws_security_group" "bad_example" {
				name        = "http"
				description = "some description"
			  
				egress  {
					  description = "ingress block description"
					  from_port   = 80
					  to_port     = 80
					  protocol    = "tcp"
					  cidr_blocks = [aws_vpc.main.cidr_block]
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
