package ecr

import (
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
)

func Adapt(modules []block.Module) ecr.ECR {
	return ecr.ECR{
		Repositories: adaptRepositories(modules),
	}
}

func adaptRepositories(modules []block.Module) []ecr.Repository {
	var repositories []ecr.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecr_repository") {
			repositories = append(repositories, adaptRepository(resource, module))
		}
	}
	return repositories
}

func adaptRepository(resource block.Block, module block.Module) ecr.Repository {

	scanOnPushVal := types.BoolDefault(false, *resource.GetMetadata())
	tagsImmutable := types.BoolDefault(false, *resource.GetMetadata())
	encryptionTypeVal := types.StringDefault("AES256", *resource.GetMetadata())
	kmsKeyVal := types.StringDefault("", *resource.GetMetadata())

	var policyDoc iam.PolicyDocument

	if resource.HasChild("image_scanning_configuration") {
		imageScanningBlock := resource.GetBlock("image_scanning_configuration")
		scanOnPushAttr := imageScanningBlock.GetAttribute("scan_on_push")
		scanOnPushVal = scanOnPushAttr.AsBoolValueOrDefault(false, imageScanningBlock)
	}

	mutabilityAttr := resource.GetAttribute("image_tag_mutability")
	if mutabilityAttr.Equals("IMMUTABLE") {
		tagsImmutable = types.Bool(true, *mutabilityAttr.GetMetadata())
	} else if mutabilityAttr.Equals("MUTABLE") {
		tagsImmutable = types.Bool(false, *mutabilityAttr.GetMetadata())
	}

	policyBlocks := module.GetReferencingResources(resource, "aws_ecr_repository_policy", "repository")
	for _, policyRes := range policyBlocks {
		if policyRes.HasChild("policy") && policyRes.GetAttribute("policy").IsString() {
			policyAttr := policyRes.GetAttribute("policy")
			rawJSON := []byte(policyAttr.Value().AsString())
			parsedPolicy, err := iam.ParsePolicyDocument(rawJSON, *policyAttr.GetMetadata())
			if err != nil {
				debug.Log("Error decoding IAM policy JSON at %s: %s", policyAttr.Range(), err)
			}
			if parsedPolicy != nil {
				policyDoc = *parsedPolicy
			}
		}
	}

	if resource.HasChild("encryption_configuration") {
		encryptBlock := resource.GetBlock("encryption_configuration")
		encryptionTypeAttr := encryptBlock.GetAttribute("encryption_type")
		encryptionTypeVal = encryptionTypeAttr.AsStringValueOrDefault("AES256", encryptBlock)

		kmsKeyAttr := encryptBlock.GetAttribute("kms_key")
		kmsKeyVal = kmsKeyAttr.AsStringValueOrDefault("", encryptBlock)
	}

	return ecr.Repository{
		Metadata: *resource.GetMetadata(),
		ImageScanning: ecr.ImageScanning{
			ScanOnPush: scanOnPushVal,
		},
		ImageTagsImmutable: tagsImmutable,
		Policy:             policyDoc,
		Encryption: ecr.Encryption{
			Type:     encryptionTypeVal,
			KMSKeyID: kmsKeyVal,
		},
	}
}
