package config

import (
	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) config.Config {
	return config.Config{}
}
