package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckPublicACLsAreBlocked = rules.RuleDef{
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
	CheckFunc: func(context *infra.Context) []*result.Result {
		var results []*result.Result
		for _, block := range context.AWS.S3.PublicAccessBlocks {
			if block.BlockPublicACLs.IsFalse() {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Public access block '%s' does not block public ACLs", block.Reference),
					Location:    block.BlockPublicACLs.Range,
				})
			}
		}
		return results
	},
}
