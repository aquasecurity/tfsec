package compute

import "github.com/aquasecurity/defsec/types"

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

func (d *Disk) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *Disk) GetRawValue() interface{} {
	return nil
}

func (d *DiskEncryption) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DiskEncryption) GetRawValue() interface{} {
	return nil
}
