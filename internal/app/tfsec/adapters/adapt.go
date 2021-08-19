package adapters

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapters/aws"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/defsec/infra"
)

func Adapt(modules []block.Module) (*infra.Context, error) {
	return &infra.Context{
		AWS: aws.Adapt(modules),
	}, nil
}
