package s3

import "github.com/aquasecurity/tfsec/pkg/defsec/definition"

type PublicAccessBlock struct {
	*definition.Metadata
	Bucket *Bucket
}
