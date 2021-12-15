package loadbalancing

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) {
	return loadbalancing{}
}
