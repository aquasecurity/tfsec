package authorization

import "github.com/aquasecurity/trivy-config-parsers/types"

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
