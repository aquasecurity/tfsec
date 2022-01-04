package mq

import (
	"github.com/aquasecurity/defsec/provider/aws/mq"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) mq.MQ {
	return mq.MQ{}
}
