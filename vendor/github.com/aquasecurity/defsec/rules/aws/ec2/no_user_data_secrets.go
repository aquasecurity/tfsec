package ec2

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoSecretsInUserData = rules.Register(
	rules.Rule{
		Provider:   provider.AWSProvider,
		Service:    "ec2",
		ShortCode:  "no-secrets-in-user-data",
		Summary:    "User data for EC2 instances must not contain sensitive AWS keys",
		Impact:     "User data is visible through the AWS Management console",
		Resolution: "Remove sensitive data from the EC2 instance user-data",
		Explanation: `
 EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.
 `,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.AWS.EC2.Instances {
			if instance.HasSensitiveInformationInUserData() {
				results.Add(
					"Instance has potentially sensitive information in its user data",
					instance.UserData.Metadata(),
				)
			}
		}
		return results
	},
)
