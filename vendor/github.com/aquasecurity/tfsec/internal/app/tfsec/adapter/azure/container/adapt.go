package container

import (
	"github.com/aquasecurity/defsec/provider/azure/container"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) container.Container {
	return container.Container{}
}
