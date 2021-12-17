package azure

import (
	"github.com/aquasecurity/defsec/provider/azure/appservice"
	"github.com/aquasecurity/defsec/provider/azure/authorization"
	"github.com/aquasecurity/defsec/provider/azure/compute"
	"github.com/aquasecurity/defsec/provider/azure/container"
	"github.com/aquasecurity/defsec/provider/azure/database"
	"github.com/aquasecurity/defsec/provider/azure/datafactory"
	"github.com/aquasecurity/defsec/provider/azure/datalake"
	"github.com/aquasecurity/defsec/provider/azure/keyvault"
	"github.com/aquasecurity/defsec/provider/azure/monitor"
	"github.com/aquasecurity/defsec/provider/azure/network"
	"github.com/aquasecurity/defsec/provider/azure/securitycenter"
	"github.com/aquasecurity/defsec/provider/azure/storage"
	"github.com/aquasecurity/defsec/provider/azure/synapse"
)

type Azure struct {
	AppService     appservice.AppService
	Authorization  authorization.Authorization
	Compute        compute.Compute
	Container      container.Container
	Database       database.Database
	DataFactory    datafactory.DataFactory
	DataLake       datalake.DataLake
	KeyVault       keyvault.KeyVault
	Monitor        monitor.Monitor
	Network        network.Network
	SecurityCenter securitycenter.SecurityCenter
	Storage        storage.Storage
	Synapse        synapse.Synapse
}
