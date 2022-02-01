package ecr

import (
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) ecr.ECR {
	return ecr.ECR{
		Repositories: adaptRepositories(modules),
	}
}

func adaptRepositories(modules block.Modules) []ecr.Repository {
	var repositories []ecr.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecr_repository") {
			repositories = append(repositories, adaptRepository(resource, module))
		}
	}
	return repositories
}

func adaptRepository(resource *block.Block, module *block.Module) ecr.Repository {
	repo := ecr.Repository{
		Metadata: resource.Metadata(),
		ImageScanning: ecr.ImageScanning{
			Metadata:   resource.Metadata(),
			ScanOnPush: types.BoolDefault(false, *resource.GetMetadata()),
		},
		ImageTagsImmutable: types.BoolDefault(false, *resource.GetMetadata()),
		Policies:           nil,
		Encryption: ecr.Encryption{
			Metadata: resource.Metadata(),
			Type:     types.StringDefault("AES256", *resource.GetMetadata()),
			KMSKeyID: types.StringDefault("", *resource.GetMetadata()),
		},
	}

	if imageScanningBlock := resource.GetBlock("image_scanning_configuration"); imageScanningBlock.IsNotNil() {
		repo.ImageScanning.Metadata = imageScanningBlock.Metadata()
		scanOnPushAttr := imageScanningBlock.GetAttribute("scan_on_push")
		repo.ImageScanning.ScanOnPush = scanOnPushAttr.AsBoolValueOrDefault(false, imageScanningBlock)
	}

	mutabilityAttr := resource.GetAttribute("image_tag_mutability")
	if mutabilityAttr.Equals("IMMUTABLE") {
		repo.ImageTagsImmutable = types.Bool(true, *mutabilityAttr.GetMetadata())
	} else if mutabilityAttr.Equals("MUTABLE") {
		repo.ImageTagsImmutable = types.Bool(false, *mutabilityAttr.GetMetadata())
	}

	policyBlocks := module.GetReferencingResources(resource, "aws_ecr_repository_policy", "repository")
	for _, policyRes := range policyBlocks {
		if policyAttr := policyRes.GetAttribute("policy"); policyAttr.IsString() {
			repo.Policies = append(repo.Policies, policyAttr.AsStringValueOrDefault("", policyRes))
		}
	}

	if encryptBlock := resource.GetBlock("encryption_configuration"); encryptBlock.IsNotNil() {
		repo.Encryption.Metadata = encryptBlock.Metadata()
		encryptionTypeAttr := encryptBlock.GetAttribute("encryption_type")
		repo.Encryption.Type = encryptionTypeAttr.AsStringValueOrDefault("AES256", encryptBlock)

		kmsKeyAttr := encryptBlock.GetAttribute("kms_key")
		repo.Encryption.KMSKeyID = kmsKeyAttr.AsStringValueOrDefault("", encryptBlock)
	}

	return repo
}
