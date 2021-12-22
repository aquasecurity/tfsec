package authorization

import (
	"github.com/aquasecurity/defsec/provider/azure/authorization"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) authorization.Authorization {
	return authorization.Authorization{}
}
