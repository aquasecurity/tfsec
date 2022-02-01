package workspaces

import (
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{
		WorkSpaces: adaptWorkspaces(modules),
	}
}

func adaptWorkspaces(modules block.Modules) []workspaces.WorkSpace {
	var workspaces []workspaces.WorkSpace
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_workspaces_workspace") {
			workspaces = append(workspaces, adaptWorkspace(resource))
		}
	}
	return workspaces
}

func adaptWorkspace(resource *block.Block) workspaces.WorkSpace {
	rootVolumeEncryptAttr := resource.GetAttribute("root_volume_encryption_enabled")
	rootVolumeEncryptVal := rootVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)

	userVolumeEncryptAttr := resource.GetAttribute("user_volume_encryption_enabled")
	userVolumeEncryptVal := userVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)

	return workspaces.WorkSpace{
		Metadata: resource.Metadata(),
		RootVolume: workspaces.Volume{
			Metadata: resource.Metadata(),
			Encryption: workspaces.Encryption{
				Metadata: resource.Metadata(),
				Enabled:  rootVolumeEncryptVal,
			},
		},
		UserVolume: workspaces.Volume{
			Metadata: resource.Metadata(),
			Encryption: workspaces.Encryption{
				Metadata: resource.Metadata(),
				Enabled:  userVolumeEncryptVal,
			},
		},
	}
}
