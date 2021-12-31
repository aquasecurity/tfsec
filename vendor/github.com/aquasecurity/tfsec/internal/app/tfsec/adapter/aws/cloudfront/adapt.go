package cloudfront

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{}
}
