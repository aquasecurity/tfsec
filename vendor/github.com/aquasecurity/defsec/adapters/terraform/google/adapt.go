package google

import (
	"github.com/aquasecurity/defsec/adapters/terraform/google/bigquery"
	"github.com/aquasecurity/defsec/adapters/terraform/google/compute"
	"github.com/aquasecurity/defsec/adapters/terraform/google/dns"
	"github.com/aquasecurity/defsec/adapters/terraform/google/gke"
	"github.com/aquasecurity/defsec/adapters/terraform/google/iam"
	"github.com/aquasecurity/defsec/adapters/terraform/google/kms"
	"github.com/aquasecurity/defsec/adapters/terraform/google/sql"
	"github.com/aquasecurity/defsec/adapters/terraform/google/storage"
	"github.com/aquasecurity/defsec/provider/google"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
)

func Adapt(modules terraform.Modules) google.Google {
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
