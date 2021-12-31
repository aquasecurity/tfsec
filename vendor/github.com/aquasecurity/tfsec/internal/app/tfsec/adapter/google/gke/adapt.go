package gke

import (
	"github.com/aquasecurity/defsec/provider/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) gke.GKE {
	return gke.GKE{}
}
