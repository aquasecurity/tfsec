package s3

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/defsec/infra"
	"github.com/aquasecurity/tfsec/pkg/result"
)

func CheckForPublicACL(context *infra.Context) []*result.Result {
	var results []*result.Result
	for _, bucket := range context.AWS.S3.Buckets {
		if bucket.HasPublicExposureACL() {
			if bucket.ACL.EqualTo("authenticated-read") {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Bucket '%s' is exposed to all AWS accounts via ACL.", bucket.Reference),
					Location:    bucket.ACL.Range,
				})
			} else {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Bucket '%s' has a public ACL: '%s'.", bucket.Reference, bucket.ACL.Value),
					Location:    bucket.ACL.Range,
				})
			}
		}
	}
	return results
}
