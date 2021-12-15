package azure

import (
	"github.com/aquasecurity/defsec/provider/azure"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/appservice"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/authorization"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/container"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/datafactory"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/datalake"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/keyvault"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/monitor"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/network"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/securitycenter"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure/synapse"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) azure.Azure {
	return azure.Azure{
		AppService:     appservice.Adapt(modules),
		Authorization:  authorization.Adapt(modules),
		Compute:        compute.Adapt(modules),
		Container:      container.Adapt(modules),
		Database:       database.Adapt(modules),
		DataFactory:    datafactory.Adapt(modules),
		DataLake:       datalake.Adapt(modules),
		KeyVault:       keyvault.Adapt(modules),
		Monitor:        monitor.Adapt(modules),
		Network:        network.Adapt(modules),
		SecurityCenter: securitycenter.Adapt(modules),
		Storage:        storage.Adapt(modules),
		Synapse:        synapse.Adapt(modules),
	}
}
