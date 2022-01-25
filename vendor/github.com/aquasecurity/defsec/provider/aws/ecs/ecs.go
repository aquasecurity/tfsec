package ecs

import "github.com/aquasecurity/defsec/types"

type ECS struct {
	types.Metadata
	Clusters        []Cluster
	TaskDefinitions []TaskDefinition
}

type Cluster struct {
	types.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	types.Metadata
	ContainerInsightsEnabled types.BoolValue
}

type TaskDefinition struct {
	types.Metadata
	Volumes              []Volume
	ContainerDefinitions types.StringValue
}

type Volume struct {
	types.Metadata
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	types.Metadata
	TransitEncryptionEnabled types.BoolValue
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}

func (v *Volume) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Volume) GetRawValue() interface{} {
	return nil
}

func (td *TaskDefinition) GetMetadata() *types.Metadata {
	return &td.Metadata
}

func (td *TaskDefinition) GetRawValue() interface{} {
	return nil
}

func (td *EFSVolumeConfiguration) GetMetadata() *types.Metadata {
	return &td.Metadata
}

func (td *EFSVolumeConfiguration) GetRawValue() interface{} {
	return nil
}


func (e *ECS) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *ECS) GetRawValue() interface{} {
	return nil
}    


func (c *ClusterSettings) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *ClusterSettings) GetRawValue() interface{} {
	return nil
}    
