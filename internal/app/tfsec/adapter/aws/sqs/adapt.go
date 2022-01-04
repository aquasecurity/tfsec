package sqs

import (
	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) sqs.SQS {
	return sqs.SQS{}
}
