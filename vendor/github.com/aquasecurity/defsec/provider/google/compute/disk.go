package compute

import "github.com/aquasecurity/defsec/types"

type Disk struct {
	Name       types.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	RawKey     types.BytesValue
	KMSKeyLink types.StringValue
}
