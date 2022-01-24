package adapter

import (
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/azure"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/cloudstack"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/digitalocean"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/github"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/google"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/kubernetes"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/openstack"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/oracle"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) *state.State {
	return &state.State{
		AWS:          aws.Adapt(modules),
		Azure:        azure.Adapt(modules),
		CloudStack:   cloudstack.Adapt(modules),
		DigitalOcean: digitalocean.Adapt(modules),
		GitHub:       github.Adapt(modules),
		Google:       google.Adapt(modules),
		Kubernetes:   kubernetes.Adapt(modules),
		OpenStack:    openstack.Adapt(modules),
		Oracle:       oracle.Adapt(modules),
	}
}
