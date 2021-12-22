package monitor

import (
	"github.com/aquasecurity/defsec/provider/azure/monitor"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) monitor.Monitor {
	return monitor.Monitor{}
}
