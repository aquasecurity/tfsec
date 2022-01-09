package lambda

import (
	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) lambda.Lambda {
	return lambda.Lambda{
		Functions: adaptFunctions(modules),
	}
}

func adaptFunctions(modules []block.Module) []lambda.Function {
	var functions []lambda.Function
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_lambda_function") {
			functions = append(functions, adaptFunction(resource, modules))
		}
	}
	return functions
}

func adaptFunction(function block.Block, modules []block.Module) lambda.Function {
	return lambda.Function{
		Metadata:    function.Metadata(),
		Tracing:     adaptTracing(function),
		Permissions: adaptPermissions(function, modules),
	}
}

func adaptTracing(function block.Block) lambda.Tracing {
	if tracingConfig := function.GetBlock("tracing_config"); tracingConfig.IsNotNil() {
		return lambda.Tracing{
			Mode: tracingConfig.GetAttribute("mode").AsStringValueOrDefault("", tracingConfig),
		}
	}

	return lambda.Tracing{
		Mode: types.StringDefault("", function.Metadata()),
	}
}

func adaptPermissions(function block.Block, modules []block.Module) []lambda.Permission {
	var permissions []lambda.Permission
	for _, module := range modules {
		for _, permission := range module.GetResourcesByType("aws_lambda_permission") {
			var functionName = function.GetAttribute("function_name").AsStringValueOrDefault("", function)
			var permissionFunctionName = permission.GetAttribute("function_name").AsStringValueOrDefault("", permission)
			if functionName.EqualTo(permissionFunctionName.Value()) {
				permissions = append(permissions, lambda.Permission{
					Principal: permission.GetAttribute("principal").AsStringValueOrDefault("", permission),
					SourceARN: permission.GetAttribute("source_arn").AsStringValueOrDefault("", permission),
				})
			}
		}
	}
	return permissions
}
