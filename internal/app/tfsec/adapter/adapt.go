package adapter

import (
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) *infra.Context {
	return &state.State{
		AWS: aws.Adapt(modules),
	}
}
