package datalake

import "github.com/aquasecurity/trivy-config-parsers/types"

type DataLake struct {
	types.Metadata
	Stores []Store
}

type Store struct {
	types.Metadata
	EnableEncryption types.BoolValue
}
