package aws

import (
	"github.com/aquasecurity/defsec/provider/aws"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/ec2"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) aws.AWS {
	return aws.AWS{
		S3:  s3.Adapt(modules),
		EC2: ec2.Adapt(modules),
	}
}
