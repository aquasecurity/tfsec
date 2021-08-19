package adapter

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/defsec/infra"
)

func Adapt(modules []block.Module) *infra.Context {
	return &infra.Context{
		AWS: aws.Adapt(modules),
	}
}
