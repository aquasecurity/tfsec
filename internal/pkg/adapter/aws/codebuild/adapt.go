package codebuild

import (
	"github.com/aquasecurity/defsec/provider/aws/codebuild"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) codebuild.CodeBuild {
	return codebuild.CodeBuild{
		Projects: adaptProjects(modules),
	}
}

func adaptProjects(modules block.Modules) []codebuild.Project {
	var projects []codebuild.Project
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_codebuild_project") {
			projects = append(projects, adaptProject(resource))
		}
	}
	return projects
}

func adaptProject(resource *block.Block) codebuild.Project {
	artifactsBlock := resource.GetBlock("artifacts")
	encryptionEnabled := types.BoolDefault(true, *resource.GetMetadata())

	if artifactsBlock.IsNotNil() {
		typeAttr := artifactsBlock.GetAttribute("type")
		encryptionDisabledAttr := artifactsBlock.GetAttribute("encryption_disabled")

		if encryptionDisabledAttr.IsTrue() && typeAttr.NotEqual("NO_ARTIFACTS") {
			encryptionEnabled = types.Bool(false, *artifactsBlock.GetMetadata())
		} else {
			encryptionEnabled = types.Bool(true, *artifactsBlock.GetMetadata())
		}
	}

	var secondaryArtifacts []codebuild.ArtifactSettings
	secondaryArtifactBlocks := resource.GetBlocks("secondary_artifacts")

	for _, secondaryArtifactBlock := range secondaryArtifactBlocks {

		secondaryEncryptionEnabled := types.BoolDefault(true, *secondaryArtifactBlock.GetMetadata())
		secondaryEncryptionDisabledAttr := secondaryArtifactBlock.GetAttribute("encryption_disabled")
		secondaryTypeAttr := artifactsBlock.GetAttribute("type")

		if secondaryEncryptionDisabledAttr.IsTrue() && secondaryTypeAttr.NotEqual("NO_ARTIFACTS") {
			secondaryEncryptionEnabled = types.Bool(false, *secondaryArtifactBlock.GetMetadata())
		}

		secondaryArtifacts = append(secondaryArtifacts, codebuild.ArtifactSettings{
			Metadata:          *secondaryArtifactBlock.GetMetadata(),
			EncryptionEnabled: secondaryEncryptionEnabled,
		})
	}

	return codebuild.Project{
		Metadata: *resource.GetMetadata(),
		ArtifactSettings: codebuild.ArtifactSettings{
			EncryptionEnabled: encryptionEnabled,
		},
		SecondaryArtifactSettings: secondaryArtifacts,
	}
}
