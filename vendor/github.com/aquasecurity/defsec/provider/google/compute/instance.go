package compute

import "github.com/aquasecurity/defsec/types"

type Instance struct {
	*types.Metadata
	Name              types.StringValue
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	*types.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP types.BoolValue
	NATIP       types.StringValue
}
