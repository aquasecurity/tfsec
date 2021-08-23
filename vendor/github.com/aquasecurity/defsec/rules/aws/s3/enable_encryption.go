package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/result"
)

func CheckEncryptionIsEnabled(context *infra.Context) []*result.Result {

	var results []*result.Result
	for _, bucket := range context.AWS.S3.Buckets {
		if bucket.Encryption.Enabled.IsFalse() {
			results = append(results, &result.Result{
				Description: fmt.Sprintf("Resource '%s' does not have encryption enabled", bucket.Reference),
				Location:    bucket.Encryption.Enabled.Range,
			})
		}
	}
	return results
}
