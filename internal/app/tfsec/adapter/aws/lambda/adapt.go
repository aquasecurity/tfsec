package lambda

import (
	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) lambda.Lambda {
	return lambda.Lambda{}
}
