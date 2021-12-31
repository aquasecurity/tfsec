package keyvault

import (
	"github.com/aquasecurity/defsec/provider/azure/keyvault"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) keyvault.KeyVault {
	return keyvault.KeyVault{}
}
