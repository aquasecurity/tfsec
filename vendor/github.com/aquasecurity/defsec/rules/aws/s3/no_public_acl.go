package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckForPublicACL = rules.Register(
	rules.Rule{
		AVDID:     "AVD-AWS-0092",
		Provider:  provider.AWSProvider,
		Service:   "s3",
		ShortCode: "no-public-access-with-acl",
		Summary:   "S3 Bucket does not have logging enabled.",
		Explanation: `
Buckets should have logging enabled so that access can be audited. 
`,
		Impact:     "There is no way to determine the access to this bucket",
		Resolution: "Add a logging block to the resource to enable access logging",

		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.HasPublicExposureACL() {
				if bucket.ACL.EqualTo("authenticated-read") {
					results.Add(
						"Bucket is exposed to all AWS accounts via ACL.",
						&bucket,
						bucket.ACL,
					)
				} else {
					results.Add(
						fmt.Sprintf("Bucket has a public ACL: '%s'.", bucket.ACL.Value()),
						&bucket,
						bucket.ACL,
					)
				}
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
