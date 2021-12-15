package synapse

import (
	"github.com/aquasecurity/defsec/provider/azure/synapse"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) synapse.Synapse {
	return synapse.Synapse{}
}
