package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptAPIsV2(modules []block.Module) []apigateway.API {

	var apis []apigateway.API

	for _, module := range modules {
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

			apis = append(apis, api)
		}
	}
	return apis
}
