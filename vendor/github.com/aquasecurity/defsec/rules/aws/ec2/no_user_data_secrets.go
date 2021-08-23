package ec2

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckNoSecretsInUserData = rules.RuleDef{

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
	CheckFunc: func(context *infra.Context) []*result.Result {

		var results []*result.Result
		for _, instance := range context.AWS.EC2.Instances {
			if instance.HasSensitiveInformationInUserData() {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Instance '%s' has potentially sensitive information in its user data", instance.Reference),
					Location:    instance.UserData.Range,
				})
			}
		}
		return results
	},
}
