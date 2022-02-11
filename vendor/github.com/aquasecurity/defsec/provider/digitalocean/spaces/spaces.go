package spaces

import "github.com/aquasecurity/trivy-config-parsers/types"

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
