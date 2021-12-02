package iam

import "github.com/aquasecurity/defsec/types"

type PasswordPolicy struct {
	types.Metadata
	ReusePreventionCount types.IntValue
	RequireLowercase     types.BoolValue
	RequireUppercase     types.BoolValue
	RequireNumbers       types.BoolValue
	RequireSymbols       types.BoolValue
	MaxAgeDays           types.IntValue
	MinimumLength        types.IntValue
}

func (p *PasswordPolicy) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *PasswordPolicy) GetRawValue() interface{} {
	return nil
}
