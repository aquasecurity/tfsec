package kubernetes

import "github.com/aquasecurity/defsec/types"

type Kubernetes struct {
	NetworkPolicies []NetworkPolicy
}

type NetworkPolicy struct {
	Spec Spec
}

type Spec struct {
	Egress  Egress
	Ingress Ingress
}

type Egress struct {
	Ports            []Port
	DestinationCIDRs []types.StringValue
}

type Ingress struct {
	Ports       []Port
	SourceCIDRs []types.StringValue
}

type Port struct {
	Number   types.StringValue // e.g. "http" or "80"
	Protocol types.StringValue
}
