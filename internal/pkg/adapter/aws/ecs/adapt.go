package ecs

import (
	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) ecs.ECS {
	return ecs.ECS{
		Clusters:        adaptClusters(modules),
		TaskDefinitions: adaptTaskDefinitions(modules),
	}
}

func adaptClusters(modules block.Modules) []ecs.Cluster {
	var clusters []ecs.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecs_cluster") {
			clusters = append(clusters, adaptClusterResource(resource))
		}
	}
	return clusters
}

func adaptClusterResource(resourceBlock *block.Block) ecs.Cluster {
	return ecs.Cluster{
		Metadata: resourceBlock.Metadata(),
		Settings: adaptClusterSettings(resourceBlock),
	}
}

func adaptClusterSettings(resourceBlock *block.Block) ecs.ClusterSettings {
	if settingBlock := resourceBlock.GetBlock("setting"); settingBlock.IsNotNil() && settingBlock.GetAttribute("name").Equals("containerInsights") {
		containerInsightsEnabled := settingBlock.GetAttribute("value").Equals("enabled")
		return ecs.ClusterSettings{
			ContainerInsightsEnabled: types.Bool(containerInsightsEnabled, settingBlock.Metadata()),
		}
	}

	return ecs.ClusterSettings{
		ContainerInsightsEnabled: types.BoolDefault(false, resourceBlock.Metadata()),
	}
}

func adaptTaskDefinitions(modules block.Modules) []ecs.TaskDefinition {
	var taskDefinitions []ecs.TaskDefinition
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecs_task_definition") {
			taskDefinitions = append(taskDefinitions, adaptTaskDefinitionResource(resource))
		}
	}
	return taskDefinitions
}

func adaptTaskDefinitionResource(resourceBlock *block.Block) ecs.TaskDefinition {
	return ecs.TaskDefinition{
		Metadata:             resourceBlock.Metadata(),
		Volumes:              adaptVolumes(resourceBlock),
		ContainerDefinitions: resourceBlock.GetAttribute("container_definitions").AsStringValueOrDefault("", resourceBlock),
	}
}

func adaptVolumes(resourceBlock *block.Block) []ecs.Volume {
	if volumeBlocks := resourceBlock.GetBlocks("volume"); len(volumeBlocks) > 0 {
		var volumes []ecs.Volume
		for _, volumeBlock := range volumeBlocks {
			volumes = append(volumes, ecs.Volume{
				Metadata:               volumeBlock.Metadata(),
				EFSVolumeConfiguration: adaptEFSVolumeConfiguration(volumeBlock),
			})
		}
		return volumes
	}

	return []ecs.Volume{}
}

func adaptEFSVolumeConfiguration(volumeBlock *block.Block) ecs.EFSVolumeConfiguration {
	if EFSConfigBlock := volumeBlock.GetBlock("efs_volume_configuration"); EFSConfigBlock.IsNotNil() {
		transitEncryptionEnabled := EFSConfigBlock.GetAttribute("transit_encryption").Equals("ENABLED")
		return ecs.EFSVolumeConfiguration{
			Metadata:                 EFSConfigBlock.Metadata(),
			TransitEncryptionEnabled: types.Bool(transitEncryptionEnabled, EFSConfigBlock.Metadata()),
		}
	}

	return ecs.EFSVolumeConfiguration{
		Metadata:                 volumeBlock.Metadata(),
		TransitEncryptionEnabled: types.BoolDefault(true, volumeBlock.Metadata()),
	}
}
