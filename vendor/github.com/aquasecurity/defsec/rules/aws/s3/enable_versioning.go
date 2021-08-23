package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckVersioningIsEnabled = rules.RuleDef{

	Provider:   provider.AWSProvider,
	Service:    "s3",
	Summary:    "S3 Data should be versioned",
	Impact:     "Deleted or modified data would not be recoverable",
	Resolution: "Enable versioning to protect against accidental/malicious removal or modification",
	Explanation: `
Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. 
You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
With versioning you can recover more easily from both unintended user actions and application failures.
`,

	Links: []string{
		"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
	},

	Severity: severity.Medium,
	CheckFunc: func(context *infra.Context) []*result.Result {

		var results []*result.Result

		for _, bucket := range context.AWS.S3.Buckets {
			if !bucket.Versioning.Enabled.IsTrue() {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Resource '%s' does not have versioning enabled", bucket.Reference),
					Location:    bucket.Versioning.Enabled.Range,
				})
			}
		}
		return results
	},
}
