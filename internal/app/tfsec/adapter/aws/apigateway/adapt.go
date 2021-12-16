package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) apigateway.APIGateway {

	var service apigateway.APIGateway

	for _, module := range modules {

		// domain names v1
		for _, nameBlock := range module.GetResourcesByType("aws_api_gateway_domain_name") {
			var domainName apigateway.DomainName
			domainName.Metadata = nameBlock.Metadata()
			domainName.Version = types.Int(1, nameBlock.Metadata())

			if name := nameBlock.GetAttribute("domain_name"); name.IsString() {
				domainName.Name = name.AsStringValue(true)
			} else {
				domainName.Name = types.StringDefault("", nameBlock.Metadata())
			}

			if policy := nameBlock.GetAttribute("security_policy"); policy.IsString() {
				domainName.SecurityPolicy = policy.AsStringValue(true)
			} else {
				domainName.SecurityPolicy = types.StringDefault("TLS_1_0", nameBlock.Metadata())
			}

			service.DomainNames = append(service.DomainNames, domainName)
		}

		// domain names v2
		for _, nameBlock := range module.GetResourcesByType("aws_apigatewayv2_domain_name") {
			var domainName apigateway.DomainName
			domainName.Metadata = nameBlock.Metadata()
			domainName.Version = types.Int(2, nameBlock.Metadata())

			if name := nameBlock.GetAttribute("domain_name"); name.IsString() {
				domainName.Name = name.AsStringValue(true)
			} else {
				domainName.Name = types.StringDefault("", nameBlock.Metadata())
			}

			if config := nameBlock.GetBlock("domain_name_configuration"); config.IsNotNil() {
				if policy := config.GetAttribute("security_policy"); policy.IsString() {
					domainName.SecurityPolicy = policy.AsStringValue(true)
				} else {
					domainName.SecurityPolicy = types.StringDefault("TLS_1_0", config.Metadata())
				}
			} else {
				domainName.SecurityPolicy = types.StringDefault("TLS_1_0", nameBlock.Metadata())
			}

			service.DomainNames = append(service.DomainNames, domainName)
		}

		// v1
		for _, apiBlock := range module.GetResourcesByType("aws_api_gateway_rest_api") {
			var api apigateway.API
			api.Metadata = apiBlock.Metadata()
			api.Version = types.Int(1, apiBlock.Metadata())
			if name := apiBlock.GetAttribute("name"); name.IsString() {
				api.Name = name.AsStringValue(true)
			} else {
				api.Name = types.StringDefault("", apiBlock.Metadata())
			}
			api.ProtocolType = types.StringDefault(apigateway.ProtocolTypeREST, apiBlock.Metadata())

			for _, methodBlock := range module.GetReferencingResources(apiBlock, "aws_api_gateway_method", "rest_api_id") {
				var method apigateway.RESTMethod

				if httpMethod := methodBlock.GetAttribute("http_method"); httpMethod.IsString() {
					method.HTTPMethod = httpMethod.AsStringValue(true)
				} else {
					method.HTTPMethod = types.StringDefault("", methodBlock.Metadata())
				}

				if auth := methodBlock.GetAttribute("authorization"); auth.IsString() {
					method.AuthorizationType = auth.AsStringValue(true)
				} else {
					method.AuthorizationType = types.StringDefault("", methodBlock.Metadata())
				}

				if apiKey := methodBlock.GetAttribute("api_key_required"); apiKey.IsBool() {
					method.APIKeyRequired = apiKey.AsBoolValue(true)
				} else {
					method.APIKeyRequired = types.BoolDefault(false, methodBlock.Metadata())
				}

				api.RESTMethods = append(api.RESTMethods, method)
			}

			var defaultCacheEncryption = types.BoolDefault(false, api.Metadata)
			for _, methodSettings := range module.GetReferencingResources(apiBlock, "aws_api_gateway_method_settings", "rest_api_id") {
				if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
					if encrypted := settings.GetAttribute("cache_data_encrypted"); encrypted.IsNotNil() {
						defaultCacheEncryption = encrypted.AsBoolValue(true)
					}
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
							stage.RESTMethodSettings.CacheDataEncrypted = encrypted.AsBoolValue(true)
						}
					}
				}

				if name := stageBlock.GetAttribute("stage_name"); name.IsString() {
					stage.Name = name.AsStringValue(true)
				} else {
					stage.Name = types.StringDefault("", stageBlock.Metadata())
				}
				if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
					stage.AccessLogging.Metadata = accessLogging.Metadata()
					if logGroupARN := accessLogging.GetAttribute("destination_arn"); logGroupARN.IsNotNil() {
						stage.AccessLogging.CloudwatchLogGroupARN = logGroupARN.AsStringValue(true)
					} else {
						stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", accessLogging.Metadata())
					}
				} else {
					stage.AccessLogging.Metadata = stageBlock.Metadata()
					stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", stageBlock.Metadata())
				}

				if xray := stageBlock.GetAttribute("xray_tracing_enabled"); xray.IsBool() {
					stage.XRayTracingEnabled = xray.AsBoolValue(true)
				} else {
					stage.XRayTracingEnabled = types.BoolDefault(false, stageBlock.Metadata())
				}

				api.Stages = append(api.Stages, stage)
			}

			service.APIs = append(service.APIs, api)
		}

		// v2
		for _, apiBlock := range module.GetResourcesByType("aws_apigatewayv2_api") {
			var api apigateway.API
			api.Metadata = apiBlock.Metadata()
			api.Version = types.IntExplicit(2, apiBlock.Metadata())
			if name := apiBlock.GetAttribute("name"); name.IsString() {
				api.Name = name.AsStringValue(true)
			} else {
				api.Name = types.StringDefault("", apiBlock.Metadata())
			}
			if protocol := apiBlock.GetAttribute("protocol_type"); protocol.IsString() {
				api.ProtocolType = protocol.AsStringValue(true)
			} else {
				api.ProtocolType = types.StringDefault("", apiBlock.Metadata())
			}

			for _, stageBlock := range module.GetReferencingResources(apiBlock, "aws_apigatewayv2_stage", "api_id") {
				var stage apigateway.Stage
				stage.Metadata = stageBlock.Metadata()
				stage.Version = types.IntExplicit(2, apiBlock.Metadata())
				if name := stageBlock.GetAttribute("name"); name.IsString() {
					stage.Name = name.AsStringValue(true)
				} else {
					stage.Name = types.StringDefault("", stageBlock.Metadata())
				}
				if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
					stage.AccessLogging.Metadata = accessLogging.Metadata()
					if logGroupARN := accessLogging.GetAttribute("destination_arn"); logGroupARN.IsNotNil() {
						stage.AccessLogging.CloudwatchLogGroupARN = logGroupARN.AsStringValue(true)
					} else {
						stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", accessLogging.Metadata())
					}
				} else {
					stage.AccessLogging.Metadata = stageBlock.Metadata()
					stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", stageBlock.Metadata())
				}

				api.Stages = append(api.Stages, stage)
			}

			service.APIs = append(service.APIs, api)
		}
	}

	return service
}
