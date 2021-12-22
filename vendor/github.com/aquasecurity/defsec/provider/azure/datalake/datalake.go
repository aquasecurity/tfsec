package datalake

import "github.com/aquasecurity/defsec/types"

type DataLake struct {
	Stores []Store
}

type Store struct {
	EnableEncryption types.BoolValue
}
