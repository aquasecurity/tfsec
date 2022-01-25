package spaces

import "github.com/aquasecurity/defsec/types"

type Spaces struct {
	types.Metadata
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
	types.Metadata
	Enabled types.BoolValue
}

type Object struct {
	types.Metadata
	ACL types.StringValue
}

func (b *Bucket) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *Bucket) GetRawValue() interface{} {
	return nil
}

func (s *Spaces) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Spaces) GetRawValue() interface{} {
	return nil
}

func (v *Versioning) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Versioning) GetRawValue() interface{} {
	return nil
}

func (o *Object) GetMetadata() *types.Metadata {
	return &o.Metadata
}

func (o *Object) GetRawValue() interface{} {
	return nil
}
