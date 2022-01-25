package workspaces

import "github.com/aquasecurity/defsec/types"

type WorkSpaces struct {
	types.Metadata
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	types.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	Enabled types.BoolValue
}

func (b *WorkSpace) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *WorkSpace) GetRawValue() interface{} {
	return nil
}


func (w *WorkSpaces) GetMetadata() *types.Metadata {
	return &w.Metadata
}

func (w *WorkSpaces) GetRawValue() interface{} {
	return nil
}    


func (v *Volume) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Volume) GetRawValue() interface{} {
	return nil
}    


func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}    
