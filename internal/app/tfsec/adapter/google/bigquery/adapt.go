package bigquery

import (
	"github.com/aquasecurity/defsec/provider/google/bigquery"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) bigquery.BigQuery {
	return bigquery.BigQuery{
		Datasets: adaptDatasets(modules),
	}
}

func adaptDatasets(modules block.Modules) []bigquery.Dataset {
	var datasets []bigquery.Dataset
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_bigquery_dataset") {
			datasets = append(datasets, adaptDataset(resource))
		}
	}
	return datasets
}

func adaptDataset(resource block.Block) bigquery.Dataset {
	IDAttr := resource.GetAttribute("dataset_id")
	IDVal := IDAttr.AsStringValueOrDefault("", resource)

	var accessGrants []bigquery.AccessGrant

	accessBlocks := resource.GetBlocks("access")
	for _, accessBlock := range accessBlocks {
		roleAttr := accessBlock.GetAttribute("role")
		roleVal := roleAttr.AsStringValueOrDefault("", accessBlock)

		domainAttr := accessBlock.GetAttribute("domain")
		domainVal := domainAttr.AsStringValueOrDefault("", accessBlock)

		specialGrAttr := accessBlock.GetAttribute("special_group")
		specialGrVal := specialGrAttr.AsStringValueOrDefault("", accessBlock)

		accessGrants = append(accessGrants, bigquery.AccessGrant{
			Role:         roleVal,
			Domain:       domainVal,
			SpecialGroup: specialGrVal,
		})
	}

	return bigquery.Dataset{
		Metadata:     *resource.GetMetadata(),
		ID:           IDVal,
		AccessGrants: accessGrants,
	}
}
