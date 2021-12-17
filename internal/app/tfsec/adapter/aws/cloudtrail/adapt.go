package cloudtrail

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) cloudtrail.CloudTrail {
	return cloudtrail.CloudTrail{}
}
