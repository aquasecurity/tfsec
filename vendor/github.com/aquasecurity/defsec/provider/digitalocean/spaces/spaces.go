package spaces

import "github.com/aquasecurity/defsec/types"

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
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
