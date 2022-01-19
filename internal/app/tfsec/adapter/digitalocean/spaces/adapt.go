package spaces

import (
	"github.com/aquasecurity/defsec/provider/digitalocean/spaces"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/google/uuid"
)

func Adapt(modules []block.Module) spaces.Spaces {
	return spaces.Spaces{
		Buckets: adaptBuckets(modules),
	}
}

func adaptBuckets(modules []block.Module) []spaces.Bucket {
	bucketMap := make(map[string]spaces.Bucket)
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
			bucketMap[block.ID()] = bucket
		}
		for _, block := range module.GetResourcesByType("digitalocean_spaces_bucket_object") {
			var object spaces.Object
			object.ACL = block.GetAttribute("acl").AsStringValueOrDefault("private", block)
			bucketName := block.GetAttribute("bucket")
			var found bool
			if bucketName.IsString() {
				for i, bucket := range bucketMap {
					if bucket.Name.Value() == bucketName.Value().AsString() {
						bucket.Objects = append(bucket.Objects, object)
						bucketMap[i] = bucket
						found = true
						break
					}
				}
				if found {
					continue
				}
			} else if bucketName.IsNotNil() {
				if referencedBlock, err := module.GetReferencedBlock(bucketName, block); err == nil {
					if bucket, ok := bucketMap[referencedBlock.ID()]; ok {
						bucket.Objects = append(bucket.Objects, object)
						bucketMap[referencedBlock.ID()] = bucket
						continue
					}
				}
			}
			bucketMap[uuid.NewString()] = spaces.Bucket{
				Metadata: types.NewUnmanagedMetadata(block.Range(), block.Reference()),
				Objects: []spaces.Object{
					object,
				},
			}
		}
	}

	var buckets []spaces.Bucket
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}
	return buckets
}
