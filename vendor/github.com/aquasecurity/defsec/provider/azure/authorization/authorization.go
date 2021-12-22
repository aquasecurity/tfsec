package authorization

import "github.com/aquasecurity/defsec/types"

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	Permissions      []Permission
	AssignableScopes []types.StringValue
}

type Permission struct {
	Actions []types.StringValue
}
