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
				Metadata:     types.NewMetadata(block.Range(), block.Reference()),
				Name:         block.GetAttribute("name").AsStringValueOrDefault("", block),
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
		for _, block := range module.GetResourcesByType("digitalocean_spaces_bucket_object") {
			var object spaces.Object
			object.ACL = block.GetAttribute("acl").AsStringValueOrDefault("private", block)
			bucketName := block.GetAttribute("bucket")
			if bucketName.IsString() {
				var found bool
				for i, bucket := range buckets {
					if bucket.Name.Value() == bucketName.Value().AsString() {
						buckets[i].Objects = append(buckets[i].Objects, object)
						found = true
						break
					}
				}
				if found {
					continue
				}
			}
			buckets = append(buckets, spaces.Bucket{
				Metadata: types.NewUnmanagedMetadata(block.Range(), block.Reference()),
				Objects: []spaces.Object{
					object,
				},
			})

		}
	}
	return buckets
}
