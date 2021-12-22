package compute

import "github.com/aquasecurity/defsec/types"

type Network struct {
	types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
