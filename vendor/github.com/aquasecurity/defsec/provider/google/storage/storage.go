package storage

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/types"
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

func (s *Storage) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Storage) GetRawValue() interface{} {
	return nil
}

func (b *Bucket) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *Bucket) GetRawValue() interface{} {
	return nil
}
