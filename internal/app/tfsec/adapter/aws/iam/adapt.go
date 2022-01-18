package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) iam.IAM {
	return iam.IAM{
		PasswordPolicy: adaptPasswordPolicy(modules),
		Policies:       adaptPolicies(modules),
		Groups:         adaptGroups(modules),
		Users:          adaptUsers(modules),
		Roles:          adaptRoles(modules),
	}
}

func adaptRoles(modules block.Modules) []iam.Role {

	roleMap := make(map[string]iam.Role)
	policyMap := make(map[string]struct{})
	var err error
	for _, roleBlock := range modules.GetResourcesByType("aws_iam_role") {
		var role iam.Role
		role.Metadata = roleBlock.Metadata()
		role.Name = roleBlock.GetAttribute("name").AsStringValueOrDefault("", roleBlock)
		if inlineBlock := roleBlock.GetBlock("inline_policy"); inlineBlock.IsNotNil() {
			var policy iam.Policy
			policy.Metadata = inlineBlock.Metadata()
			policy.Name = inlineBlock.GetAttribute("name").AsStringValueOrDefault("", inlineBlock)
			policy.Document, err = parsePolicyFromAttr(inlineBlock.GetAttribute("policy"), inlineBlock, modules)
			if err != nil {
				continue
			}
			role.Policies = append(role.Policies, policy)
		}

		for _, block := range modules.GetResourcesByType("aws_iam_role_policy") {
			if !sameProvider(roleBlock, block) {
				continue
			}
			if roleAttr := block.GetAttribute("role"); roleAttr.IsString() {
				if roleAttr.Equals(role.Name.Value()) {
					policy, err := parsePolicy(block, modules)
					if err != nil {
						continue
					}
					role.Policies = append(role.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_role_policy_attachment") {
			if !sameProvider(roleBlock, block) {
				continue
			}
			if roleAttr := block.GetAttribute("role"); roleAttr.IsString() {
				if roleAttr.Equals(role.Name.Value()) {
					policyAttr := block.GetAttribute("policy_arn")

					policyBlock, err := modules.GetReferencedBlock(policyAttr, block)
					if err != nil {
						continue
					}
					policy, err := parsePolicy(policyBlock, modules)
					if err != nil {
						continue
					}
					role.Policies = append(role.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		roleMap[roleBlock.ID()] = role
	}

	for _, policyBlock := range modules.GetResourcesByType("aws_iam_role_policy") {
		if _, ok := policyMap[policyBlock.ID()]; ok {
			continue
		}
		roleAttr := policyBlock.GetAttribute("role")
		if roleAttr.IsNil() {
			continue
		}
		roleBlock, err := modules.GetReferencedBlock(roleAttr, policyBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		role := roleMap[roleBlock.ID()]
		role.Policies = append(role.Policies, policy)
		roleMap[roleBlock.ID()] = role
	}

	var output []iam.Role
	for _, role := range roleMap {
		output = append(output, role)
	}
	return output
}

func adaptUsers(modules block.Modules) []iam.User {
	userMap := make(map[string]iam.User)
	policyMap := make(map[string]struct{})
	for _, userBlock := range modules.GetResourcesByType("aws_iam_user") {
		var user iam.User
		user.Metadata = userBlock.Metadata()
		user.Name = userBlock.GetAttribute("name").AsStringValueOrDefault("", userBlock)

		for _, block := range modules.GetResourcesByType("aws_iam_user_policy") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); userAttr.IsString() {
				if userAttr.Equals(user.Name.Value()) {
					policy, err := parsePolicy(block, modules)
					if err != nil {
						continue
					}
					user.Policies = append(user.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_user_policy_attachment") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); userAttr.IsString() {
				if userAttr.Equals(user.Name.Value()) {
					policyAttr := block.GetAttribute("policy_arn")

					policyBlock, err := modules.GetReferencedBlock(policyAttr, block)
					if err != nil {
						continue
					}
					policy, err := parsePolicy(policyBlock, modules)
					if err != nil {
						continue
					}
					user.Policies = append(user.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		userMap[userBlock.ID()] = user
	}

	for _, policyBlock := range modules.GetResourcesByType("aws_iam_user_policy") {
		if _, ok := policyMap[policyBlock.ID()]; ok {
			continue
		}
		userAttr := policyBlock.GetAttribute("user")
		if userAttr.IsNil() {
			continue
		}
		userBlock, err := modules.GetReferencedBlock(userAttr, policyBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		user := userMap[userBlock.ID()]
		user.Policies = append(user.Policies, policy)
		userMap[userBlock.ID()] = user
	}

	var output []iam.User
	for _, user := range userMap {
		output = append(output, user)
	}
	return output
}

func sameProvider(b1, b2 block.Block) bool {

	if b1.HasChild("provider") != b2.HasChild("provider") {
		return false
	}

	var provider1, provider2 string
	if providerAttr := b1.GetAttribute("provider"); providerAttr.IsString() {
		provider1 = providerAttr.Value().AsString()
	}
	if providerAttr := b2.GetAttribute("provider"); providerAttr.IsString() {
		provider2 = providerAttr.Value().AsString()
	}
	return strings.EqualFold(provider1, provider2)
}

func parsePolicy(policyBlock block.Block, modules block.Modules) (iam.Policy, error) {
	var policy iam.Policy
	policy.Metadata = policyBlock.Metadata()
	policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
	var err error
	policy.Document, err = parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, modules)
	if err != nil {
		return policy, err
	}
	return policy, nil

}

func adaptGroups(modules block.Modules) []iam.Group {
	groupMap := make(map[string]iam.Group)
	policyMap := make(map[string]struct{})
	for _, groupBlock := range modules.GetResourcesByType("aws_iam_group") {
		var group iam.Group
		group.Metadata = groupBlock.Metadata()
		group.Name = groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock)

		for _, block := range modules.GetResourcesByType("aws_iam_group_policy") {
			if !sameProvider(groupBlock, block) {
				continue
			}
			if groupAttr := block.GetAttribute("group"); groupAttr.IsString() {
				if groupAttr.Equals(group.Name.Value()) {
					policy, err := parsePolicy(block, modules)
					if err != nil {
						continue
					}
					group.Policies = append(group.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_group_policy_attachment") {
			if !sameProvider(groupBlock, block) {
				continue
			}
			if groupAttr := block.GetAttribute("group"); groupAttr.IsString() {
				if groupAttr.Equals(group.Name.Value()) {
					policyAttr := block.GetAttribute("policy_arn")

					policyBlock, err := modules.GetReferencedBlock(policyAttr, block)
					if err != nil {
						continue
					}
					policy, err := parsePolicy(policyBlock, modules)
					if err != nil {
						continue
					}
					group.Policies = append(group.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		groupMap[groupBlock.ID()] = group
	}

	for _, policyBlock := range modules.GetResourcesByType("aws_iam_group_policy") {
		if _, ok := policyMap[policyBlock.ID()]; ok {
			continue
		}
		groupAttr := policyBlock.GetAttribute("group")
		if groupAttr.IsNil() {
			continue
		}
		groupBlock, err := modules.GetReferencedBlock(groupAttr, policyBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		group := groupMap[groupBlock.ID()]
		group.Policies = append(group.Policies, policy)
		groupMap[groupBlock.ID()] = group
	}

	for _, attachBlock := range modules.GetResourcesByType("aws_iam_group_policy_attachment") {
		groupAttr := attachBlock.GetAttribute("group")
		if groupAttr.IsNil() {
			continue
		}
		groupBlock, err := modules.GetReferencedBlock(groupAttr, attachBlock)
		if err != nil {
			continue
		}
		policyAttr := attachBlock.GetAttribute("policy_arn")
		if policyAttr.IsNil() {
			continue
		}
		policyBlock, err := modules.GetReferencedBlock(policyAttr, attachBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		group := groupMap[groupBlock.ID()]
		group.Policies = append(group.Policies, policy)
		groupMap[groupBlock.ID()] = group
	}

	var output []iam.Group
	for _, group := range groupMap {
		output = append(output, group)
	}
	return output
}

func adaptPolicies(modules block.Modules) (policies []iam.Policy) {
	var err error
	for _, policyBlock := range modules.GetResourcesByType("aws_iam_policy") {
		var policy iam.Policy
		policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
		policy.Document, err = parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, modules)
		if err != nil {
			continue
		}
		policies = append(policies, policy)
	}
	return
}
