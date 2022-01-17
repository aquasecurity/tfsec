package msk

import (
	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) msk.MSK {
	return msk.MSK{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules []block.Module) []msk.Cluster {
	var clusters []msk.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_msk_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource block.Block) msk.Cluster {
	clientBrokerVal := types.StringDefault("TLS_PLAINTEXT", *resource.GetMetadata())

	s3enabled := types.BoolDefault(false, *resource.GetMetadata())
	cloudwatchEnabled := types.BoolDefault(false, *resource.GetMetadata())
	firehoseEnabled := types.BoolDefault(false, *resource.GetMetadata())

	if resource.HasChild("encryption_info") {
		encryptBlock := resource.GetBlock("encryption_info")
		if encryptBlock.HasChild("encryption_in_transit") {
			encryptionInTransitBlock := encryptBlock.GetBlock("encryption_in_transit")
			clientBrokerAttr := encryptionInTransitBlock.GetAttribute("client_broker")
			if clientBrokerAttr.IsNotNil() {
				clientBrokerVal = clientBrokerAttr.AsStringValueOrDefault("TLS", encryptionInTransitBlock)
			}
		}
	}

	if resource.HasChild("logging_info") {
		logBlock := resource.GetBlock("logging_info")
		if logBlock.HasChild("broker_logs") {
			brokerLogsBlock := logBlock.GetBlock("broker_logs")

			if brokerLogsBlock.HasChild("s3") {
				s3Block := brokerLogsBlock.GetBlock("s3")
				s3enabledAttr := s3Block.GetAttribute("enabled")
				s3enabled = s3enabledAttr.AsBoolValueOrDefault(false, s3Block)
			}
			if brokerLogsBlock.HasChild("cloudwatch_logs") {
				cloudwatchBlock := brokerLogsBlock.GetBlock("cloudwatch_logs")
				cwEnabledAttr := cloudwatchBlock.GetAttribute("enabled")
				cloudwatchEnabled = cwEnabledAttr.AsBoolValueOrDefault(false, cloudwatchBlock)
			}
			if brokerLogsBlock.HasChild("firehose") {
				firehoseBlock := brokerLogsBlock.GetBlock("firehose")
				firehoseEnabledAttr := firehoseBlock.GetAttribute("enabled")
				firehoseEnabled = firehoseEnabledAttr.AsBoolValueOrDefault(false, firehoseBlock)
			}
		}
	}

	return msk.Cluster{
		Metadata: *resource.GetMetadata(),
		EncryptionInTransit: msk.EncryptionInTransit{
			ClientBroker: clientBrokerVal,
		},
		Logging: msk.Logging{
			Broker: msk.BrokerLogging{
				S3: msk.S3Logging{
					Enabled: s3enabled,
				},
				Cloudwatch: msk.CloudwatchLogging{
					Enabled: cloudwatchEnabled,
				},
				Firehose: msk.FirehoseLogging{
					Enabled: firehoseEnabled,
				},
			},
		},
	}
}
