package datalake

import (
	"github.com/aquasecurity/defsec/provider/azure/datalake"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) datalake.DataLake {
	return datalake.DataLake{}
}
