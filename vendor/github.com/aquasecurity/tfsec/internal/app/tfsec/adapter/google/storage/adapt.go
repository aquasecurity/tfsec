package storage

import (
	"github.com/aquasecurity/defsec/provider/google/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) storage.Storage {
	return storage.Storage{
		Buckets: adaptBuckets(modules),
	}
}

func adaptBuckets(modules []block.Module) []storage.Bucket {
	var buckets []storage.Bucket
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_storage_bucket") {
			buckets = append(buckets, adaptBucketResource(resource))
		}
	}
	return buckets
}

func adaptBucketResource(resourceBlock block.Block) storage.Bucket {

	nameAttr := resourceBlock.GetAttribute("name")
	nameValue := nameAttr.AsStringValueOrDefault("", resourceBlock)

	locationAttr := resourceBlock.GetAttribute("location")
	locationValue := locationAttr.AsStringValueOrDefault("", resourceBlock)

	// See https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#uniform_bucket_level_access
	ublaAttr := resourceBlock.GetAttribute("uniform_bucket_level_access")
	ublaValue := ublaAttr.AsBoolValueOrDefault(false, resourceBlock)

	return storage.Bucket{
		Name:                           nameValue,
		Location:                       locationValue,
		EnableUniformBucketLevelAccess: ublaValue,
	}
}
