package datafactory

import (
	"github.com/aquasecurity/defsec/provider/azure/datafactory"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) datafactory.DataFactory {
	return datafactory.DataFactory{}
}
