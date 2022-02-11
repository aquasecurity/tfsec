package storage

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

type Storage struct {
	types.Metadata
	Buckets []Bucket
}

type Bucket struct {
	types.Metadata
	Name                           types.StringValue
	Location                       types.StringValue
	EnableUniformBucketLevelAccess types.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
}
