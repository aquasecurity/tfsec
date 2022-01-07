package spaces

import (
	"github.com/aquasecurity/defsec/types"

	"github.com/aquasecurity/defsec/provider/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) spaces.Spaces {
	return spaces.Spaces{
		Buckets: adaptBuckets(modules),
	}
}

func adaptBuckets(modules []block.Module) []spaces.Bucket {
	var buckets []spaces.Bucket

	for _, module := range modules {
		for _, resourceBlock := range module.GetResourcesByType("digitalocean_spaces_bucket") {
			bucket := adaptBucket(resourceBlock)
			for _, objectBlock := range module.GetReferencingResources(resourceBlock, "digitalocean_spaces_bucket_object", "bucket") {
				bucket.Objects = append(bucket.Objects, adaptObject(objectBlock))
			}
			buckets = append(buckets, bucket)
		}
	}
	return buckets
}

func adaptBucket(resourceBlock block.Block) spaces.Bucket {
	aclAttr := resourceBlock.GetAttribute("acl")
	aclVal := aclAttr.AsStringValueOrDefault("", resourceBlock)

	forceDestroyAttr := resourceBlock.GetAttribute("force_destroy")
	forceDestroyVal := forceDestroyAttr.AsBoolValueOrDefault(false, resourceBlock)

	versioningBlock := resourceBlock.GetBlock("versioning")
	enabledVal := types.Bool(false, *resourceBlock.GetMetadata())
	if versioningBlock.IsNotNil() {
		enabledAttr := versioningBlock.GetAttribute("enabled")
		enabledVal = enabledAttr.AsBoolValueOrDefault(false, versioningBlock)
	}

	return spaces.Bucket{
		ACL:          aclVal,
		ForceDestroy: forceDestroyVal,
		Versioning: spaces.Versioning{
			Enabled: enabledVal,
		},
	}
}

func adaptObject(resource block.Block) spaces.Object {
	aclAttr := resource.GetAttribute("acl")
	aclVal := aclAttr.AsStringValueOrDefault("", resource)

	return spaces.Object{
		ACL: aclVal,
	}
}
