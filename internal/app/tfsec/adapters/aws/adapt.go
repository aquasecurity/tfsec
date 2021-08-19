package aws

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/defsec/aws"
)

func Adapt(modules []block.Module) aws.AWS {
	return aws.AWS{
		S3: s3.Adapt(modules),
	}
}
