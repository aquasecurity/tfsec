package iam

import (
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

	var err error

	roleMap := make(map[string]iam.Role)
	for _, module := range modules {
		for _, roleBlock := range module.GetResourcesByType("aws_iam_role") {
			var role iam.Role
			role.Metadata = roleBlock.Metadata()
			role.Name = roleBlock.GetAttribute("name").AsStringValueOrDefault("", roleBlock)

			if inlineBlock := roleBlock.GetBlock("inline_policy"); inlineBlock.IsNotNil() {
				var policy iam.Policy
				policy.Name = inlineBlock.GetAttribute("name").AsStringValueOrDefault("", inlineBlock)
				policy.Document, err = parsePolicyFromAttr(inlineBlock.GetAttribute("policy"), inlineBlock, module)
				if err != nil {
					continue
				}
				role.Policies = append(role.Policies, policy)
			}

			roleMap[roleBlock.ID()] = role
		}

		for _, policyBlock := range module.GetResourcesByType("aws_iam_role_policy") {
			roleAttr := policyBlock.GetAttribute("role")
			if roleAttr.IsNil() {
				continue
			}
			roleBlock, err := module.GetReferencedBlock(roleAttr, policyBlock)
			if err != nil {
				continue
			}
			var policy iam.Policy
			policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
			policy.Document, err = parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, module)
			if err != nil {
				continue
			}
			role := roleMap[roleBlock.ID()]
			role.Policies = append(role.Policies, policy)
			roleMap[roleBlock.ID()] = role
		}
	}

	var output []iam.Role
	for _, role := range roleMap {
		output = append(output, role)
	}
	return output
}

func adaptUsers(modules block.Modules) []iam.User {
	userMap := make(map[string]iam.User)
	for _, module := range modules {
		for _, userBlock := range module.GetResourcesByType("aws_iam_user") {
			var user iam.User
			user.Metadata = userBlock.Metadata()
			user.Name = userBlock.GetAttribute("name").AsStringValueOrDefault("", userBlock)
			userMap[userBlock.ID()] = user
		}

		for _, policyBlock := range module.GetResourcesByType("aws_iam_user_policy") {
			userAttr := policyBlock.GetAttribute("user")
			if userAttr.IsNil() {
				continue
			}
			userBlock, err := module.GetReferencedBlock(userAttr, policyBlock)
			if err != nil {
				continue
			}
			var policy iam.Policy
			policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
			policy.Document, err = parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, module)
			if err != nil {
				continue
			}
			user := userMap[userBlock.ID()]
			user.Policies = append(user.Policies, policy)
			userMap[userBlock.ID()] = user
		}
	}

	var output []iam.User
	for _, user := range userMap {
		output = append(output, user)
	}
	return output
}

func adaptGroups(modules block.Modules) []iam.Group {
	groupMap := make(map[string]iam.Group)
	for _, module := range modules {
		for _, groupBlock := range module.GetResourcesByType("aws_iam_group") {
			var group iam.Group
			group.Metadata = groupBlock.Metadata()
			group.Name = groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock)
			groupMap[groupBlock.ID()] = group
		}

		for _, policyBlock := range module.GetResourcesByType("aws_iam_group_policy") {
			groupAttr := policyBlock.GetAttribute("group")
			if groupAttr.IsNil() {
				continue
			}
			groupBlock, err := module.GetReferencedBlock(groupAttr, policyBlock)
			if err != nil {
				continue
			}
			var policy iam.Policy
			policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
			policy.Document, err = parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, module)
			if err != nil {
				continue
			}
			group := groupMap[groupBlock.ID()]
			group.Policies = append(group.Policies, policy)
			groupMap[groupBlock.ID()] = group
		}
	}

	var output []iam.Group
	for _, group := range groupMap {
		output = append(output, group)
	}
	return output
}

func adaptPolicies(modules block.Modules) (policies []iam.Policy) {
	var err error
	for _, module := range modules {
		for _, policyBlock := range module.GetResourcesByType("aws_iam_policy") {
			var policy iam.Policy
			policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
			policy.Document, err = parsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, module)
			if err != nil {
				continue
			}
			policies = append(policies, policy)
		}
	}
	return
}
