package iam

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptPasswordPolicy(modules block.Modules) (policy iam.PasswordPolicy) {
	passwordPolicies := modules.GetResourcesByType("aws_iam_account_password_policy")
	if len(passwordPolicies) == 0 {
		return policy
	}

	// aws only allows a single password policy resource
	policyBlock := passwordPolicies[0]

	if attr := policyBlock.GetAttribute("require_lowercase_characters"); attr.IsNotNil() {
		policy.RequireLowercase = types.BoolExplicit(attr.IsTrue(), attr.Metadata())
	} else {
		policy.RequireLowercase = types.BoolDefault(false, policyBlock.Metadata())
	}
	if attr := policyBlock.GetAttribute("require_uppercase_characters"); attr.IsNotNil() {
		policy.RequireUppercase = types.BoolExplicit(attr.IsTrue(), attr.Metadata())
	} else {
		policy.RequireUppercase = types.BoolDefault(false, policyBlock.Metadata())
	}
	if attr := policyBlock.GetAttribute("require_numbers"); attr.IsNotNil() {
		policy.RequireNumbers = types.BoolExplicit(attr.IsTrue(), attr.Metadata())
	} else {
		policy.RequireNumbers = types.BoolDefault(false, policyBlock.Metadata())
	}
	if attr := policyBlock.GetAttribute("require_symbols"); attr.IsNotNil() {
		policy.RequireSymbols = types.BoolExplicit(attr.IsTrue(), attr.Metadata())
	} else {
		policy.RequireSymbols = types.BoolDefault(false, policyBlock.Metadata())
	}
	if attr := policyBlock.GetAttribute("password_reuse_prevention"); attr.IsNumber() {
		value, _ := attr.Value().AsBigFloat().Float64()
		policy.ReusePreventionCount = types.IntExplicit(int(value), attr.Metadata())
	} else {
		policy.ReusePreventionCount = types.IntDefault(0, policyBlock.Metadata())
	}
	if attr := policyBlock.GetAttribute("max_password_age"); attr.IsNumber() {
		value, _ := attr.Value().AsBigFloat().Float64()
		policy.MaxAgeDays = types.IntExplicit(int(value), attr.Metadata())
	} else {
		policy.MaxAgeDays = types.IntDefault(0, policyBlock.Metadata())
	}
	if attr := policyBlock.GetAttribute("minimum_password_length"); attr.IsNumber() {
		value, _ := attr.Value().AsBigFloat().Float64()
		policy.MinimumLength = types.IntExplicit(int(value), attr.Metadata())
	} else {
		policy.MinimumLength = types.IntDefault(0, policyBlock.Metadata())
	}

	return policy
}
