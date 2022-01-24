package lambda

import (
	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) lambda.Lambda {

	adapter := adapter{
		permissionIDs: modules.GetChildResourceIDMapByType("aws_lambda_permission"),
	}

	return lambda.Lambda{
		Functions: adapter.adaptFunctions(modules),
	}
}

type adapter struct {
	permissionIDs block.ResourceIDResolutions
}

func (a *adapter) adaptFunctions(modules block.Modules) []lambda.Function {

	var functions []lambda.Function
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_lambda_function") {
			functions = append(functions, a.adaptFunction(resource, modules))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.permissionIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := lambda.Function{
			Metadata: types.NewUnmanagedMetadata(),
		}
		for _, permission := range orphanResources {
			orphanage.Permissions = append(orphanage.Permissions, a.adaptPermission(permission))
		}
		functions = append(functions, orphanage)
	}

	return functions
}

func (a *adapter) adaptFunction(function *block.Block, modules block.Modules) lambda.Function {
	return lambda.Function{
		Metadata:    function.Metadata(),
		Tracing:     a.adaptTracing(function),
		Permissions: a.adaptPermissions(modules),
	}
}

func (a *adapter) adaptTracing(function *block.Block) lambda.Tracing {
	if tracingConfig := function.GetBlock("tracing_config"); tracingConfig.IsNotNil() {
		return lambda.Tracing{
			Mode: tracingConfig.GetAttribute("mode").AsStringValueOrDefault("", tracingConfig),
		}
	}

	return lambda.Tracing{
		Mode: types.StringDefault("", function.Metadata()),
	}
}

func (a *adapter) adaptPermissions(modules block.Modules) []lambda.Permission {
	var permissions []lambda.Permission
	for _, module := range modules {
		for _, p := range module.GetResourcesByType("aws_lambda_permission") {

			permissions = append(permissions, a.adaptPermission(p))
		}
	}
	return permissions
}

func (a *adapter) adaptPermission(permission *block.Block) lambda.Permission {
	return lambda.Permission{
		Principal: permission.GetAttribute("principal").AsStringValueOrDefault("", permission),
		SourceARN: permission.GetAttribute("source_arn").AsStringValueOrDefault("", permission),
	}
}
