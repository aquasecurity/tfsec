package neptune

import (
	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) neptune.Neptune {
	return neptune.Neptune{}
}
