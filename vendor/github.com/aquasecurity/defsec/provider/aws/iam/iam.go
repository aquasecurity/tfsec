package iam

type IAM struct {
	PasswordPolicy PasswordPolicy
	Policies       []Policy
	GroupPolicies  []GroupPolicy
	UserPolicies   []UserPolicy
	RolePolicies   []RolePolicy
}

type Policy struct {
	Document PolicyDocument
}

type GroupPolicy struct {
	Document PolicyDocument
}

type UserPolicy struct {
	Document PolicyDocument
}

type RolePolicy struct {
	Document PolicyDocument
}
