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
			api.Name = apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock)
			api.ProtocolType = apiBlock.GetAttribute("protocol_type").AsStringValueOrDefault("", apiBlock)

			for _, stageBlock := range module.GetReferencingResources(apiBlock, "aws_apigatewayv2_stage", "api_id") {
				var stage apigateway.Stage
				stage.Metadata = stageBlock.Metadata()
				stage.Version = types.IntExplicit(2, apiBlock.Metadata())
				stage.Name = stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock)
				if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
					stage.AccessLogging.Metadata = accessLogging.Metadata()
					stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
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
