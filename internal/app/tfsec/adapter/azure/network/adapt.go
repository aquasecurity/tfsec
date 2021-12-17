package network

import (
	"github.com/aquasecurity/defsec/provider/azure/network"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) network.Network {
	return network.Network{}
}
