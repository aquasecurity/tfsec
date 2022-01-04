package authorization

import (
	"github.com/aquasecurity/defsec/provider/azure/authorization"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) authorization.Authorization {
	return authorization.Authorization{
		RoleDefinitions: adaptRoleDefinitions(modules),
	}
}

func adaptRoleDefinitions(modules []block.Module) []authorization.RoleDefinition {
	var roleDefinitions []authorization.RoleDefinition
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_role_definition") {
			roleDefinitions = append(roleDefinitions, adaptRoleDefinition(resource))
		}
	}
	return roleDefinitions
}

func adaptRoleDefinition(resource block.Block) authorization.RoleDefinition {
	permissionsBlocks := resource.GetBlocks("permissions")
	var permissionsVal []authorization.Permission

	for _, permissionsBlock := range permissionsBlocks {
		actionsAttr := permissionsBlock.GetAttribute("actions")
		var actionsVal []types.StringValue
		actions := actionsAttr.ValueAsStrings()
		for _, action := range actions {
			actionsVal = append(actionsVal, types.String(action, *permissionsBlock.GetMetadata()))
		}
		permissionsVal = append(permissionsVal, authorization.Permission{
			Actions: actionsVal,
		})
	}

	assignableScopesAttr := resource.GetAttribute("assignable_scopes")
	var assignableScopesVal []types.StringValue
	assignableScopes := assignableScopesAttr.ValueAsStrings()
	for _, scope := range assignableScopes {
		assignableScopesVal = append(assignableScopesVal, types.String(scope, *resource.GetMetadata()))
	}

	return authorization.RoleDefinition{
		Permissions:      permissionsVal,
		AssignableScopes: assignableScopesVal,
	}
}
