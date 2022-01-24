package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func adaptAPIsV2(modules block.Modules) []apigateway.API {

	var apis []apigateway.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_apigatewayv2_stage")

	for _, module := range modules {
		for _, apiBlock := range module.GetResourcesByType("aws_apigatewayv2_api") {
			var api apigateway.API
			api.Metadata = apiBlock.Metadata()
			api.Version = types.IntExplicit(2, apiBlock.Metadata())
			api.Name = apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock)
			api.ProtocolType = apiBlock.GetAttribute("protocol_type").AsStringValueOrDefault("", apiBlock)

			for _, stageBlock := range module.GetReferencingResources(apiBlock, "aws_apigatewayv2_stage", "api_id") {
				apiStageIDs.Resolve(stageBlock.ID())

				stage := adaptStageV2(stageBlock)

				api.Stages = append(api.Stages, stage)
			}

			apis = append(apis, api)
		}
	}

	orphanResources := modules.GetResourceByIDs(apiStageIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := apigateway.API{
			Metadata: types.NewUnmanagedMetadata(),
		}
		for _, stage := range orphanResources {
			orphanage.Stages = append(orphanage.Stages, adaptStageV2(stage))
		}
		apis = append(apis, orphanage)
	}

	return apis
}

func adaptStageV2(stageBlock *block.Block) apigateway.Stage {
	var stage apigateway.Stage
	stage.Metadata = stageBlock.Metadata()
	stage.Version = types.IntExplicit(2, stageBlock.Metadata())
	stage.Name = stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock)
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.Metadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.Metadata()
		stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", stageBlock.Metadata())
	}
	return stage
}
