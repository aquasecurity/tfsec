package ec2

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSEC2InstanceSensitiveUserdata(t *testing.T) {
	expectedCode := "aws-ec2-no-secrets-in-user-data"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "test block containing access keys",
			source: `
resource "aws_instance" "bad_example" {

  ami           = "ami-12345667"
  instance_type = "t2.small"

  user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
EOF
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "test block with no user data",
			source: `
resource "aws_iam_instance_profile" "good_profile" {
    // ...
}

resource "aws_instance" "good_example" {
  ami           = "ami-12345667"
  instance_type = "t2.small"

  iam_instance_profile = aws_iam_instance_profile.good_profile.arn
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "test block with no user data",
			source: `
resource "aws_iam_instance_profile" "good_profile" {
    // ...
}

resource "aws_instance" "good_example" {
  ami           = "ami-12345667"
  instance_type = "t2.small"

  iam_instance_profile = aws_iam_instance_profile.good_profile.arn

  user_data = "echo Hello, World! > /var/tmp/hello"
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
