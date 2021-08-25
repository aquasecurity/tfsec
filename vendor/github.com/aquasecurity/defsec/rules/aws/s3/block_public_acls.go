package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPublicACLsAreBlocked = rules.Register(
	rules.Rule{
		Provider:   provider.AWSProvider,
		Service:    "s3",
		ShortCode:  "block-public-acls",
		Summary:    "S3 Access block should block public ACL",
		Impact:     "PUT calls with public ACLs specified can make objects public",
		Resolution: "Enable blocking any PUT calls with a public ACL specified",
		Explanation: `
S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, block := range s.AWS.S3.PublicAccessBlocks {
			if block.BlockPublicACLs.IsFalse() {
				results.Add(
					"Public access block does not block public ACLs",
					block.BlockPublicACLs.Metadata(),
					block.BlockPublicACLs.Value(),
				)
			}
		}
		return results
	},
)
