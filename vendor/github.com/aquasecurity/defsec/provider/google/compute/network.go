package compute

import "github.com/aquasecurity/defsec/types"

type Network struct {
	types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}


func (n *Network) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *Network) GetRawValue() interface{} {
	return nil
}    
