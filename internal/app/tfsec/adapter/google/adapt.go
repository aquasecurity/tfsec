package google

import (
	"github.com/aquasecurity/defsec/provider/google"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/bigquery"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/dns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/kms"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/sql"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) google.Google {
	return google.Google{
		BigQuery: bigquery.Adapt(modules),
		Compute:  compute.Adapt(modules),
		DNS:      dns.Adapt(modules),
		GKE:      gke.Adapt(modules),
		KMS:      kms.Adapt(modules),
		IAM:      iam.Adapt(modules),
		SQL:      sql.Adapt(modules),
		Storage:  storage.Adapt(modules),
	}
}
