package azure

import (
	"github.com/aquasecurity/defsec/provider/azure"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/appservice"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/authorization"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/compute"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/container"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/database"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/datafactory"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/datalake"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/keyvault"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/monitor"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/network"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/securitycenter"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/storage"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure/synapse"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) azure.Azure {
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
