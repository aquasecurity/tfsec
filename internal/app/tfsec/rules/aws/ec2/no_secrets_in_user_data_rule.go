package ec2

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS062",
		Service:   "ec2",
		ShortCode: "no-secrets-in-user-data",
		Documentation: rule.RuleDocumentation{
			Summary:    "User data for EC2 instances must not contain sensitive AWS keys",
			Impact:     "User data is visible through the AWS Management console",
			Resolution: "Remove sensitive data from the EC2 instance user-data",
			Explanation: `
EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.
`,
			BadExample: []string{`
resource "aws_instance" "bad_example" {

  ami           = "ami-12345667"
  instance_type = "t2.small"

  user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
EOF
}
`},
			GoodExample: []string{`
resource "aws_iam_instance_profile" "good_example" {
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_instance"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("user_data") {
				return
			}

			userDataAttr := resourceBlock.GetAttribute("user_data")
			if userDataAttr.Contains("AWS_ACCESS_KEY_ID", block.IgnoreCase) &&
				userDataAttr.RegexMatches("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}") {
				set.AddResult().
					WithDescription("Resource '%s' has userdata with access key id defined.", resourceBlock.FullName()).
					WithAttribute(userDataAttr)
			}

			if userDataAttr.Contains("AWS_SECRET_ACCESS_KEY", block.IgnoreCase) &&
				userDataAttr.RegexMatches("(?i)aws_secre.+[=:]\\s{0,}[A-Za-z0-9\\/+=]{40}.?") {
				set.AddResult().
					WithDescription("Resource '%s' has userdata with access secret key defined.", resourceBlock.FullName()).
					WithAttribute(userDataAttr)
			}
		},
	})
}
