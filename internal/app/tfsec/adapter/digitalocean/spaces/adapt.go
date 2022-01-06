package spaces

import (
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
		for _, block := range module.GetResourcesByType("digitalocean_spaces_bucket") {
			bucket := spaces.Bucket{
				ACL:          block.GetAttribute("acl").AsStringValueOrDefault("", block),
				ForceDestroy: block.GetAttribute("force_destroy").AsBoolValueOrDefault(false, block),
			}
			versioning := block.GetBlock("versioning")
			if versioning != nil {
				v := spaces.Versioning{
					Enabled: versioning.GetAttribute("enabled").AsBoolValueOrDefault(false, versioning),
				}
				bucket.Versioning = v
			}
			buckets = append(buckets, bucket)
		}
	}
	return buckets
}
