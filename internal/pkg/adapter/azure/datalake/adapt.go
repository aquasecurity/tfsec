package datalake

import (
	"github.com/aquasecurity/defsec/provider/azure/datalake"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) datalake.DataLake {
	return datalake.DataLake{
		Stores: adaptStores(modules),
	}
}

func adaptStores(modules block.Modules) []datalake.Store {
	var stores []datalake.Store

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_data_lake_store") {
			stores = append(stores, adaptStore(resource))
		}
	}
	return stores
}

func adaptStore(resource *block.Block) datalake.Store {
	encryptionStateAttr := resource.GetAttribute("encryption_state")

	if encryptionStateAttr.Equals("Disabled") {
		return datalake.Store{
			EnableEncryption: types.Bool(false, *resource.GetMetadata()),
		}
	}
	return datalake.Store{
		EnableEncryption: types.Bool(true, *resource.GetMetadata()),
	}
}
