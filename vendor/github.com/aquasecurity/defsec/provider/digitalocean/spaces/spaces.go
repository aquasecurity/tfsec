package spaces

import "github.com/aquasecurity/defsec/types"

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
	types.Metadata
	Name         types.StringValue
	Objects      []Object
	ACL          types.StringValue
	ForceDestroy types.BoolValue
	Versioning   Versioning
}

type Versioning struct {
	Enabled types.BoolValue
}

type Object struct {
	ACL types.StringValue
}

func (b *Bucket) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *Bucket) GetRawValue() interface{} {
	return nil
}
