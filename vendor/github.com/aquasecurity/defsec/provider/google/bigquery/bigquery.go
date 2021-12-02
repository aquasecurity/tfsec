package bigquery

import "github.com/aquasecurity/defsec/types"

type BigQuery struct {
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
	Role         types.StringValue
	Domain       types.StringValue
	SpecialGroup types.StringValue
}
