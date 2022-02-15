package iam

import "github.com/aquasecurity/trivy-config-parsers/types"

type IAM struct {
	types.Metadata
	PasswordPolicy PasswordPolicy
	Policies       []Policy
	Groups         []Group
	Users          []User
	Roles          []Role
}

type Policy struct {
	types.Metadata
	Name     types.StringValue
	Document types.StringValue
}

type Group struct {
	types.Metadata
	Name     types.StringValue
	Users    []User
	Policies []Policy
}

type User struct {
	types.Metadata
	Name     types.StringValue
	Groups   []Group
	Policies []Policy
}

type Role struct {
	types.Metadata
	Name     types.StringValue
	Policies []Policy
}
