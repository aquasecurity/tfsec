package workspaces

import (
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{}
}
