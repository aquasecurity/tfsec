package openstack

import "github.com/aquasecurity/defsec/types"

type OpenStack struct {
	Compute Compute
}

type Compute struct {
	Instances []Instance
	Firewall  Firewall
}

type Firewall struct {
	AllowRules []Rule
	DenyRules  []Rule
}

type Rule struct {
	Source          types.StringValue
	Destination     types.StringValue
	SourcePort      types.StringValue
	DestinationPort types.StringValue
	Enabled         types.BoolValue
}

type Instance struct {
	AdminPassword types.StringValue
}
