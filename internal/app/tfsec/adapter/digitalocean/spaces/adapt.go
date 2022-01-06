package spaces

import (
	"github.com/aquasecurity/defsec/provider/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) spaces.Spaces {
	return spaces.Spaces{
		Buckets: []spaces.Bucket{},
	}
}

func adaptBuckets(modules block.Modules) []spaces.Bucket {
	var buckets []spaces.Bucket
	for _, module := range modules {
		for _, block := range module.GetBlocksByTypeLabel("digitalocean_spaces_bucket") {
			bucket := spaces.Bucket{
				ACL:          block.GetAttribute("acl").AsStringValueOrDefault("", block),
				ForceDestroy: block.GetAttribute("force_destroy").AsBoolValueOrDefault(false, block),
			}
			versioning := block.GetBlock("versioning")
			if versioning != nil {
				bucket.Versioning.Enabled = versioning.GetAttribute("enabled").AsBoolValueOrDefault(false, versioning)
			}
			buckets = append(buckets, bucket)
		}
	}
	return buckets
}
