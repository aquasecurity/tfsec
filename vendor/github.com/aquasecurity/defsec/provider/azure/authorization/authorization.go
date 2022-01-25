package authorization

import "github.com/aquasecurity/defsec/types"

type Authorization struct {
	types.Metadata
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	types.Metadata
	Permissions      []Permission
	AssignableScopes []types.StringValue
}

type Permission struct {
	types.Metadata
	Actions []types.StringValue
}

func (a *Authorization) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *Authorization) GetRawValue() interface{} {
	return nil
}

func (r *RoleDefinition) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *RoleDefinition) GetRawValue() interface{} {
	return nil
}

func (p *Permission) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *Permission) GetRawValue() interface{} {
	return nil
}
