package securitycenter

import (
	"github.com/aquasecurity/defsec/provider/azure/securitycenter"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) securitycenter.SecurityCenter {
	return securitycenter.SecurityCenter{}
}
