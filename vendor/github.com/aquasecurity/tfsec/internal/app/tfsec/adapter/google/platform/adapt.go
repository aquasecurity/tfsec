package platform

import (
	"github.com/aquasecurity/defsec/provider/google/platform"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) platform.Platform {
	return platform.Platform{}
}
