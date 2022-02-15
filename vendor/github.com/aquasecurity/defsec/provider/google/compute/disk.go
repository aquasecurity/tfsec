package compute

import "github.com/aquasecurity/trivy-config-parsers/types"

type Disk struct {
	types.Metadata
	Name       types.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	types.Metadata
	RawKey     types.BytesValue
	KMSKeyLink types.StringValue
}
