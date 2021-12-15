package adapter

import (
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/azure"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/cloudstack"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/digitalocean"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/github"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/google"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/kubernetes"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/openstack"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/oracle"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
