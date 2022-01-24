package mq

import (
	"github.com/aquasecurity/defsec/provider/aws/mq"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) mq.MQ {
	return mq.MQ{
		Brokers: adaptBrokers(modules),
	}
}

func adaptBrokers(modules block.Modules) []mq.Broker {
	var brokers []mq.Broker
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_mq_broker") {
			brokers = append(brokers, adaptBroker(resource))
		}
	}
	return brokers
}

func adaptBroker(resource *block.Block) mq.Broker {
	publicAccessAttr := resource.GetAttribute("publicly_accessible")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(false, resource)

	auditVal := types.Bool(false, *resource.GetMetadata())
	generalVal := types.Bool(false, *resource.GetMetadata())

	if resource.HasChild("logs") {
		logsBlock := resource.GetBlock("logs")

		auditAttr := logsBlock.GetAttribute("audit")
		auditVal = auditAttr.AsBoolValueOrDefault(false, logsBlock)

		generalAttr := logsBlock.GetAttribute("general")
		generalVal = generalAttr.AsBoolValueOrDefault(false, logsBlock)
	}

	return mq.Broker{
		Metadata:     *resource.GetMetadata(),
		PublicAccess: publicAccessVal,
		Logging: mq.Logging{
			General: generalVal,
			Audit:   auditVal,
		},
	}
}
