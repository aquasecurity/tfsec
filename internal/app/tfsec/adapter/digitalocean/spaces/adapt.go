package spaces

import (
	"github.com/aquasecurity/defsec/provider/digitalocean/spaces"
	"github.com/aquasecurity/defsec/types"
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

			if versioning := block.GetBlock("versioning"); versioning.IsNotNil() {
				bucket.Versioning = spaces.Versioning{
					Enabled: versioning.GetAttribute("enabled").AsBoolValueOrDefault(false, versioning),
				}
			} else {
				bucket.Versioning = spaces.Versioning{
					Enabled: types.Bool(false, *block.GetMetadata()),
				}
			}
			buckets = append(buckets, bucket)
		}
	}
	return buckets
}
