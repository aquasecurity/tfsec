package state

import (
	"github.com/aquasecurity/defsec/provider/aws"
	"github.com/aquasecurity/defsec/provider/azure"
	"github.com/aquasecurity/defsec/provider/cloudstack"
	"github.com/aquasecurity/defsec/provider/digitalocean"
	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/defsec/provider/google"
	"github.com/aquasecurity/defsec/provider/kubernetes"
	"github.com/aquasecurity/defsec/provider/openstack"
	"github.com/aquasecurity/defsec/provider/oracle"
)

type State struct {
	AWS          aws.AWS
	Azure        azure.Azure
	CloudStack   cloudstack.CloudStack
	DigitalOcean digitalocean.DigitalOcean
	GitHub       github.GitHub
	Google       google.Google
	Kubernetes   kubernetes.Kubernetes
	OpenStack    openstack.OpenStack
	Oracle       oracle.Oracle
}
