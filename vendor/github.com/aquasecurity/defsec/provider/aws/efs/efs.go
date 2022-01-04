package efs

import "github.com/aquasecurity/defsec/types"

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	types.Metadata
	Encrypted types.BoolValue
}

func (f *FileSystem) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *FileSystem) GetRawValue() interface{} {
	return nil
}
