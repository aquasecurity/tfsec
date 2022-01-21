package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func sameProvider(b1, b2 *block.Block) bool {

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

func parsePolicy(policyBlock *block.Block, modules block.Modules) (iam.Policy, error) {
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
