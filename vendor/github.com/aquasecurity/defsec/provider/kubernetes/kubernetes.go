package kubernetes

import "github.com/aquasecurity/trivy-config-parsers/types"

type Kubernetes struct {
	types.Metadata
	NetworkPolicies []NetworkPolicy
}

type NetworkPolicy struct {
	types.Metadata
	Spec Spec
}

type Spec struct {
	types.Metadata
	Egress  Egress
	Ingress Ingress
}

type Egress struct {
	types.Metadata
	Ports            []Port
	DestinationCIDRs []types.StringValue
}

type Ingress struct {
	types.Metadata
	Ports       []Port
	SourceCIDRs []types.StringValue
}

type Port struct {
	types.Metadata
	Number   types.StringValue // e.g. "http" or "80"
	Protocol types.StringValue
}
