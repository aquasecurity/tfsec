package bigquery

import "github.com/aquasecurity/defsec/types"

type BigQuery struct {
	types.Metadata
	Datasets []Dataset
}

type Dataset struct {
	types.Metadata
	ID           types.StringValue
	AccessGrants []AccessGrant
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	types.Metadata
	Role         types.StringValue
	Domain       types.StringValue
	SpecialGroup types.StringValue
}


func (b *BigQuery) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *BigQuery) GetRawValue() interface{} {
	return nil
}    


func (d *Dataset) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *Dataset) GetRawValue() interface{} {
	return nil
}    


func (a *AccessGrant) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *AccessGrant) GetRawValue() interface{} {
	return nil
}    
