package redshift

import (
	"github.com/aquasecurity/defsec/provider/aws/redshift"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) redshift.Redshift {
	return redshift.Redshift{}
}
