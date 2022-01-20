package iam

import "github.com/aquasecurity/defsec/types"

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


func (i *IAM) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *IAM) GetRawValue() interface{} {
	return nil
}    


func (p *Policy) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *Policy) GetRawValue() interface{} {
	return nil
}    


func (g *Group) GetMetadata() *types.Metadata {
	return &g.Metadata
}

func (g *Group) GetRawValue() interface{} {
	return nil
}    


func (u *User) GetMetadata() *types.Metadata {
	return &u.Metadata
}

func (u *User) GetRawValue() interface{} {
	return nil
}    


func (r *Role) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *Role) GetRawValue() interface{} {
	return nil
}    
