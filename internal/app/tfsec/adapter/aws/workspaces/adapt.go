package workspaces

import (
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{
		WorkSpaces: adaptWorkspaces(modules),
	}
}

func adaptWorkspaces(modules []block.Module) []workspaces.WorkSpace {
	var workspaces []workspaces.WorkSpace
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_workspaces_workspace") {
			workspaces = append(workspaces, adaptWorkspace(resource))
		}
	}
	return workspaces
}

func adaptWorkspace(resource block.Block) workspaces.WorkSpace {
	rootVolumeEncryptAttr := resource.GetAttribute("root_volume_encryption_enabled")
	rootVolumeEncryptVal := rootVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)

	userVolumeEncryptAttr := resource.GetAttribute("user_volume_encryption_enabled")
	userVolumeEncryptVal := userVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)

	return workspaces.WorkSpace{
		Metadata: *resource.GetMetadata(),
		RootVolume: workspaces.Volume{
			Encryption: workspaces.Encryption{
				Enabled: rootVolumeEncryptVal,
			},
		},
		UserVolume: workspaces.Volume{
			Encryption: workspaces.Encryption{
				Enabled: userVolumeEncryptVal,
			},
		},
	}
}
