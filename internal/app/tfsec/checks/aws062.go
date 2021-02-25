package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEC2InstanceSensitiveUserdata scanner.RuleCode = "AWS062"
const AWSEC2InstanceSensitiveUserdataDescription scanner.RuleSummary = "User data for EC2 instances must not contain sensitive AWS keys"
const AWSEC2InstanceSensitiveUserdataExplanation = `
EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.
`
const AWSEC2InstanceSensitiveUserdataBadExample = `
resource "aws_instance" "bad_example" {

  ami           = "ami-12345667"
  instance_type = "t2.small"

  user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
EOF
}
`
const AWSEC2InstanceSensitiveUserdataGoodExample = `
resource "aws_iam_instance_profile" "good_profile" {
    // ...
}

resource "aws_instance" "good_example" {
  ami           = "ami-12345667"
  instance_type = "t2.small"

  iam_instance_profile = aws_iam_instance_profile.good_profile.arn

  user_data = <<EOF
  export GREETING=hello
EOF
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEC2InstanceSensitiveUserdata,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEC2InstanceSensitiveUserdataDescription,
			Explanation: AWSEC2InstanceSensitiveUserdataExplanation,
			BadExample:  AWSEC2InstanceSensitiveUserdataBadExample,
			GoodExample: AWSEC2InstanceSensitiveUserdataGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("user_data") {
				return nil
			}

			userData := block.GetAttribute("user_data")
			if userData.Contains("AWS_ACCESS_KEY_ID", parser.IgnoreCase) &&
				userData.RegexMatches("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}") {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has userdata with access key id defined.", block.FullName()),
						userData.Range(),
						userData,
						scanner.SeverityError,
					),
				}
			}

			if userData.Contains("AWS_SECRET_ACCESS_KEY", parser.IgnoreCase) &&
				userData.RegexMatches("(?i)aws_secre.+[=:]\\s{0,}[A-Za-z0-9\\/+=]{40}.?") {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has userdata with access secret key defined.", block.FullName()),
						userData.Range(),
						userData,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
