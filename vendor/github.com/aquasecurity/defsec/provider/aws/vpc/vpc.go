package vpc

import "github.com/aquasecurity/defsec/types"

type VPC struct {
	DefaultVPCs    []DefaultVPC
	SecurityGroups []SecurityGroup
	NetworkACLs    []NetworkACL
}

type NetworkACL struct {
	types.Metadata
	Rules []NetworkACLRule
}

type SecurityGroup struct {
	types.Metadata
	Description  types.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	types.Metadata
	Description types.StringValue
	CIDRs       []types.StringValue
}

type DefaultVPC struct {
	types.Metadata
}

const (
	TypeIngress = "ingress"
	TypeEgress  = "egress"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

type NetworkACLRule struct {
	types.Metadata
	Type     types.StringValue
	Action   types.StringValue
	Protocol types.IntValue
	CIDRs    []types.StringValue
}

func (v *DefaultVPC) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *DefaultVPC) GetRawValue() interface{} {
	return nil
}

func (v *SecurityGroup) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *SecurityGroup) GetRawValue() interface{} {
	return nil
}

func (v *SecurityGroupRule) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *SecurityGroupRule) GetRawValue() interface{} {
	return nil
}
func (v *NetworkACLRule) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *NetworkACLRule) GetRawValue() interface{} {
	return nil
}
