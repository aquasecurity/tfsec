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

func (e *DiskEncryption) UsesDefaultKey() bool {
	return len(e.RawKey.Value()) == 0 && e.KMSKeyLink.IsEmpty()
}
