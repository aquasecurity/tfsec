package oracle

import (
	"github.com/aquasecurity/defsec/provider/oracle"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) oracle.Oracle {
	return oracle.Oracle{
		Compute: oracle.Compute{},
	}
}
