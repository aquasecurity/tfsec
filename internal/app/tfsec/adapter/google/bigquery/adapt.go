package bigquery

import (
	"github.com/aquasecurity/defsec/provider/google/bigquery"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) bigquery.BigQuery {
	return bigquery.BigQuery{}
}
