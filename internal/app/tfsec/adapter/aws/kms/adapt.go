package kms

import (
	"github.com/aquasecurity/defsec/provider/aws/kms"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) kms.KMS {
	return kms.KMS{}
}
