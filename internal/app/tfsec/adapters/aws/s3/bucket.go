package s3

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapters"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/defsec/aws/s3"
	"github.com/aquasecurity/tfsec/pkg/defsec/definition"
)

type Adapter struct {
	modules []block.Module
}

func (a *Adapter) GetBuckets() []s3.Bucket {
	var buckets []s3.Bucket
	blocks := adapters.GetBlocksByTypeLabel("aws_s3_bucket", a.modules...)

	for _, block := range blocks {
		buckets = append(buckets, s3.Bucket{
			Metadata: definition.NewMetadata(block.Range().Filename, block.Range().StartLine, block.Range().EndLine),
		})
	}

	return buckets
}

func (s *Adapter) GetPublicAccessBlock() []s3.PublicAccessBlock {
	panic("not implemented") // TODO: Implement
}
