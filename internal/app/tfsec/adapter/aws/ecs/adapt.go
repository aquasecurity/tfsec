package ecs

import (
	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) ecs.ECS {
	return ecs.ECS{}
}
