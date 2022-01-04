package sns

import (
	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) sns.SNS {
	return sns.SNS{}
}
