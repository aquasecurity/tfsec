package iam

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/google/uuid"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam

func (a *adapter) adaptOrganizationIAM(modules block.Modules) {
	a.adaptOrganizationMembers(modules)
	a.adaptOrganizationBindings(modules)
}

func (a *adapter) adaptOrganizationMembers(modules block.Modules) {
	for _, iamBlock := range modules.GetResourcesByType("google_organization_iam_member") {
		member := a.adaptMember(iamBlock)
		organizationAttr := iamBlock.GetAttribute("organization")

		if refBlock, err := modules.GetReferencedBlock(organizationAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_organization" {
				a.addOrg(refBlock.ID())
				org := a.orgs[refBlock.ID()]
				org.Members = append(org.Members, member)
				a.orgs[refBlock.ID()] = org
				continue
			}
		}

		// we didn't find the organization - add an unmanaged one
		placeholderID := uuid.NewString()
		org := iam.Organization{
			Members: []iam.Member{member},
		}
		a.orgs[placeholderID] = org

	}
}

func (a *adapter) adaptOrganizationBindings(modules block.Modules) {
	for _, iamBlock := range modules.GetResourcesByType("google_organization_iam_binding") {
		binding := a.adaptBinding(iamBlock)
		organizationAttr := iamBlock.GetAttribute("organization")

		if refBlock, err := modules.GetReferencedBlock(organizationAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_organization" {
				a.addOrg(refBlock.ID())
				org := a.orgs[refBlock.ID()]
				org.Bindings = append(org.Bindings, binding)
				a.orgs[refBlock.ID()] = org
				continue
			}
		}

		// we didn't find the organization - add an unmanaged one
		placeholderID := uuid.NewString()
		org := iam.Organization{
			Bindings: []iam.Binding{binding},
		}
		a.orgs[placeholderID] = org
	}
}
