package compute

import "github.com/aquasecurity/trivy-config-parsers/types"

type Network struct {
	types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
