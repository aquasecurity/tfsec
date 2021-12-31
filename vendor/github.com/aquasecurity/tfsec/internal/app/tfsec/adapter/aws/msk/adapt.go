package msk

import (
	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) msk.MSK {
	return msk.MSK{}
}
