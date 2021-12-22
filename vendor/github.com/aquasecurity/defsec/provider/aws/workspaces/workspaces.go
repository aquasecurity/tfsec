package workspaces

import "github.com/aquasecurity/defsec/types"

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	types.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	Encryption Encryption
}

type Encryption struct {
	Enabled types.BoolValue
}

func (b *WorkSpace) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *WorkSpace) GetRawValue() interface{} {
	return nil
}
