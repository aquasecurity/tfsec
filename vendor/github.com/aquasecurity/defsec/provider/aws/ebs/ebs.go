package ebs

import "github.com/aquasecurity/trivy-config-parsers/types"

type EBS struct {
	types.Metadata
	Volumes []Volume
}

type Volume struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}
