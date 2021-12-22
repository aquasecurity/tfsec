package sam

import "github.com/aquasecurity/defsec/types"

type SimpleTable struct {
	types.Metadata
	TableName        types.StringValue
	SSESpecification SSESpecification
}

type SSESpecification struct {
	types.Metadata

	Enabled        types.BoolValue
	KMSMasterKeyID types.StringValue
}

func (a *SimpleTable) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *SimpleTable) GetRawValue() interface{} {
	return nil
}

func (a *SSESpecification) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *SSESpecification) GetRawValue() interface{} {
	return nil
}
