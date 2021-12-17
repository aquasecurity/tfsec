package athena

import (
	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) athena.Athena {
	return athena.Athena{}
}
