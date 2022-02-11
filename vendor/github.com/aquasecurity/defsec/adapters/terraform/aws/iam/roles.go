package iam

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
)

func adaptRoles(modules terraform.Modules) []iam.Role {

	roleMap, policyMap := mapRoles(modules)

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

func mapRoles(modules terraform.Modules) (map[string]iam.Role, map[string]struct{}) {
	policyMap := make(map[string]struct{})
	roleMap := make(map[string]iam.Role)
	var err error
	for _, roleBlock := range modules.GetResourcesByType("aws_iam_role") {
		var role iam.Role
		role.Metadata = roleBlock.GetMetadata()
		role.Name = roleBlock.GetAttribute("name").AsStringValueOrDefault("", roleBlock)
		if inlineBlock := roleBlock.GetBlock("inline_policy"); inlineBlock.IsNotNil() {
			var policy iam.Policy
			policy.Metadata = inlineBlock.GetMetadata()
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

	return roleMap, policyMap

}
