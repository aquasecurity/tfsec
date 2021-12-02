package storage

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/types"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	EnableUniformBucketLevelAccess types.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
}
