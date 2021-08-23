package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckPublicACLsAreIgnored = rules.RuleDef{
	Provider:   provider.AWSProvider,
	Service:    "s3",
	ShortCode:  "ignore-public-acls",
	Summary:    "S3 Access Block should Ignore Public Acl",
	Impact:     "PUT calls with public ACLs specified can make objects public",
	Resolution: "Enable ignoring the application of public ACLs in PUT calls",
	Explanation: `
S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.
`,
	Links: []string{
		"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
	},
	Severity: severity.High,
	CheckFunc: func(context *infra.Context) []*result.Result {
		var results []*result.Result
		for _, block := range context.AWS.S3.PublicAccessBlocks {
			if block.IgnorePublicACLs.IsFalse() {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Public access block '%s' does not ignore public ACLs", block.Reference),
					Location:    block.IgnorePublicACLs.Range,
				})
			}
		}
		return results
	},
}
