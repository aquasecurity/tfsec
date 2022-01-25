package datalake

import "github.com/aquasecurity/defsec/types"

type DataLake struct {
	types.Metadata
	Stores []Store
}

type Store struct {
	types.Metadata
	EnableEncryption types.BoolValue
}

func (d *DataLake) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DataLake) GetRawValue() interface{} {
	return nil
}

func (s *Store) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Store) GetRawValue() interface{} {
	return nil
}
