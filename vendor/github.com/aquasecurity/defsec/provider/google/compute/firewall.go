package compute

import "github.com/aquasecurity/defsec/types"

type Firewall struct {
	*types.Metadata
	IngressRules []IngressRule
	EgressRules  []EgressRule
}

type FirewallRule struct {
	*types.Metadata
	Enforced types.BoolValue
	IsAllow  types.BoolValue
}

type IngressRule struct {
	*types.Metadata
	FirewallRule
	Source types.StringValue
}

type EgressRule struct {
	*types.Metadata
	FirewallRule
	Destination types.StringValue
}
