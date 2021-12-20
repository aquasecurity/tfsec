package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptAPIMethodsV1(module block.Module, apiBlock block.Block) []apigateway.RESTMethod {
	var methods []apigateway.RESTMethod
	for _, methodBlock := range module.GetReferencingResources(apiBlock, "aws_api_gateway_method", "rest_api_id") {
		var method apigateway.RESTMethod
		method.HTTPMethod = methodBlock.GetAttribute("http_method").AsStringValueOrDefault("", methodBlock)
		method.AuthorizationType = methodBlock.GetAttribute("authorization").AsStringValueOrDefault("", methodBlock)
		method.APIKeyRequired = methodBlock.GetAttribute("api_key_required").AsBoolValueOrDefault(false, methodBlock)
		methods = append(methods, method)
	}
	return methods
}

func adaptAPIsV1(modules []block.Module) []apigateway.API {

	var apis []apigateway.API

	for _, module := range modules {

		for _, apiBlock := range module.GetResourcesByType("aws_api_gateway_rest_api") {
			var api apigateway.API
			api.Metadata = apiBlock.Metadata()
			api.Version = types.Int(1, apiBlock.Metadata())
			api.Name = apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock)
			api.ProtocolType = types.StringDefault(apigateway.ProtocolTypeREST, apiBlock.Metadata())
			api.RESTMethods = adaptAPIMethodsV1(module, apiBlock)

			var defaultCacheEncryption = types.BoolDefault(false, api.Metadata)
			for _, methodSettings := range module.GetReferencingResources(apiBlock, "aws_api_gateway_method_settings", "rest_api_id") {
				if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
					defaultCacheEncryption = settings.GetAttribute("cache_data_encrypted").AsBoolValueOrDefault(false, settings)
				}
			}

			for _, stageBlock := range module.GetReferencingResources(apiBlock, "aws_api_gateway_stage", "rest_api_id") {
				var stage apigateway.Stage
				stage.Metadata = stageBlock.Metadata()
				stage.Version = types.Int(1, apiBlock.Metadata())

				stage.RESTMethodSettings.CacheDataEncrypted = defaultCacheEncryption
				for _, methodSettings := range module.GetReferencingResources(stageBlock, "aws_api_gateway_method_settings", "stage_name") {
					if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
						if encrypted := settings.GetAttribute("cache_data_encrypted"); encrypted.IsNotNil() {
							stage.RESTMethodSettings.CacheDataEncrypted = settings.GetAttribute("cache_data_encrypted").AsBoolValueOrDefault(false, settings)
						}
					}
				}

				stage.Name = stageBlock.GetAttribute("stage_name").AsStringValueOrDefault("", stageBlock)
				if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
					stage.AccessLogging.Metadata = accessLogging.Metadata()
					stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
				} else {
					stage.AccessLogging.Metadata = stageBlock.Metadata()
					stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", stageBlock.Metadata())
				}

				stage.XRayTracingEnabled = stageBlock.GetAttribute("xray_tracing_enabled").AsBoolValueOrDefault(false, stageBlock)

				api.Stages = append(api.Stages, stage)
			}

			apis = append(apis, api)
		}
	}
	return apis
}
