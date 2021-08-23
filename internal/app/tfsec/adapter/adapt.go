package adapter

import (
	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) *infra.Context {
	return &infra.Context{
		AWS: aws.Adapt(modules),
	}
}
