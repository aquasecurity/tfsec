package appservice

import (
	"github.com/aquasecurity/defsec/provider/azure/appservice"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) appservice.AppService {
	return appservice.AppService{}
}
