package codebuild

import "github.com/aquasecurity/defsec/types"

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	types.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	types.Metadata
	EncryptionEnabled types.BoolValue
}

func (c *Project) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Project) GetRawValue() interface{} {
	return nil
}

func (c *ArtifactSettings) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *ArtifactSettings) GetRawValue() interface{} {
	return nil
}
