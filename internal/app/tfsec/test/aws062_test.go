package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEC2InstanceSensitiveUserdata(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
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
			mustIncludeResultCode: checks.AWSEC2InstanceSensitiveUserdata,
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
			mustExcludeResultCode: checks.AWSEC2InstanceSensitiveUserdata,
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
			mustExcludeResultCode: checks.AWSEC2InstanceSensitiveUserdata,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
