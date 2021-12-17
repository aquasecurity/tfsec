package kubernetes

import (
	"github.com/aquasecurity/defsec/provider/kubernetes"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) kubernetes.Kubernetes {
	return kubernetes.Kubernetes{
		NetworkPolicies: nil,
	}
}
