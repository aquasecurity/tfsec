package cloudwatch

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) cloudwatch.CloudWatch {
	return cloudwatch.CloudWatch{}
}
