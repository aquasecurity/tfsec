package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

func adaptAPIsV2(modules terraform.Modules) []apigateway.API {

	var apis []apigateway.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_apigatewayv2_stage")

	for _, module := range modules {
		for _, apiBlock := range module.GetResourcesByType("aws_apigatewayv2_api") {
			var api apigateway.API
			api.Metadata = apiBlock.GetMetadata()
			api.Version = types.IntExplicit(2, apiBlock.GetMetadata())
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

func adaptStageV2(stageBlock *terraform.Block) apigateway.Stage {
	stage := apigateway.Stage{
		Metadata: stageBlock.GetMetadata(),
		Version:  types.Int(2, stageBlock.GetMetadata()),
		RESTMethodSettings: apigateway.RESTMethodSettings{
			Metadata:           stageBlock.GetMetadata(),
			CacheDataEncrypted: types.BoolDefault(true, stageBlock.GetMetadata()),
		},
		AccessLogging: apigateway.AccessLogging{
			Metadata:              stageBlock.GetMetadata(),
			CloudwatchLogGroupARN: types.StringDefault("", stageBlock.GetMetadata()),
		},
	}
	stage.Name = stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock)
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = types.StringDefault("", stageBlock.GetMetadata())
	}
	return stage
}
