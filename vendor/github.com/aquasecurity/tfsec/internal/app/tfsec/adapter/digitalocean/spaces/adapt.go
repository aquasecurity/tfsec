package spaces

import (
	"github.com/aquasecurity/defsec/provider/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) spaces.Spaces {
	return spaces.Spaces{}
}
