package msk

import (
	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) msk.MSK {
	return msk.MSK{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules block.Modules) []msk.Cluster {
	var clusters []msk.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_msk_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *block.Block) msk.Cluster {
	cluster := msk.Cluster{
		Metadata: resource.Metadata(),
		EncryptionInTransit: msk.EncryptionInTransit{
			Metadata:     resource.Metadata(),
			ClientBroker: types.StringDefault("TLS_PLAINTEXT", resource.Metadata()),
		},
		Logging: msk.Logging{
			Metadata: resource.Metadata(),
			Broker: msk.BrokerLogging{
				Metadata: resource.Metadata(),
				S3: msk.S3Logging{
					Metadata: resource.Metadata(),
					Enabled:  types.BoolDefault(false, resource.Metadata()),
				},
				Cloudwatch: msk.CloudwatchLogging{
					Metadata: resource.Metadata(),
					Enabled:  types.BoolDefault(false, resource.Metadata()),
				},
				Firehose: msk.FirehoseLogging{
					Metadata: resource.Metadata(),
					Enabled:  types.BoolDefault(false, resource.Metadata()),
				},
			},
		},
	}

	if encryptBlock := resource.GetBlock("encryption_info"); encryptBlock.IsNotNil() {
		if encryptionInTransitBlock := encryptBlock.GetBlock("encryption_in_transit"); encryptionInTransitBlock.IsNotNil() {
			cluster.EncryptionInTransit.Metadata = encryptBlock.Metadata()
			if clientBrokerAttr := encryptionInTransitBlock.GetAttribute("client_broker"); clientBrokerAttr.IsNotNil() {
				cluster.EncryptionInTransit.ClientBroker = clientBrokerAttr.AsStringValueOrDefault("TLS", encryptionInTransitBlock)
			}
		}
	}

	if logBlock := resource.GetBlock("logging_info"); logBlock.IsNotNil() {
		cluster.Logging.Metadata = logBlock.Metadata()
		if brokerLogsBlock := logBlock.GetBlock("broker_logs"); brokerLogsBlock.IsNotNil() {
			cluster.Logging.Broker.Metadata = brokerLogsBlock.Metadata()
			if brokerLogsBlock.HasChild("s3") {
				if s3Block := brokerLogsBlock.GetBlock("s3"); s3Block.IsNotNil() {
					s3enabledAttr := s3Block.GetAttribute("enabled")
					cluster.Logging.Broker.S3.Metadata = s3Block.Metadata()
					cluster.Logging.Broker.S3.Enabled = s3enabledAttr.AsBoolValueOrDefault(false, s3Block)
				}
			}
			if cloudwatchBlock := brokerLogsBlock.GetBlock("cloudwatch_logs"); cloudwatchBlock.IsNotNil() {
				cwEnabledAttr := cloudwatchBlock.GetAttribute("enabled")
				cluster.Logging.Broker.Cloudwatch.Metadata = cloudwatchBlock.Metadata()
				cluster.Logging.Broker.Cloudwatch.Enabled = cwEnabledAttr.AsBoolValueOrDefault(false, cloudwatchBlock)
			}
			if firehoseBlock := brokerLogsBlock.GetBlock("firehose"); firehoseBlock.IsNotNil() {
				firehoseEnabledAttr := firehoseBlock.GetAttribute("enabled")
				cluster.Logging.Broker.Firehose.Metadata = firehoseEnabledAttr.Metadata()
				cluster.Logging.Broker.Firehose.Enabled = firehoseEnabledAttr.AsBoolValueOrDefault(false, firehoseBlock)
			}
		}
	}

	return cluster
}
