package iam

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func parsePolicyBlock(block block.Block) []iam.Binding {
	var bindings []iam.Binding
	for _, bindingBlock := range block.GetBlocks("binding") {
		var binding iam.Binding
		binding.Role = bindingBlock.GetAttribute("role").AsStringValueOrDefault("", bindingBlock)
		membersAttr := bindingBlock.GetAttribute("members")
		for _, member := range membersAttr.ValueAsStrings() {
			binding.Members = append(binding.Members, types.String(member, membersAttr.Metadata()))
		}
		bindings = append(bindings, binding)
	}
	return bindings
}
