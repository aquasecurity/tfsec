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

	broker := mq.Broker{
		Metadata:     resource.Metadata(),
		PublicAccess: types.BoolDefault(false, resource.Metadata()),
		Logging: mq.Logging{
			Metadata: resource.Metadata(),
			General:  types.BoolDefault(false, resource.Metadata()),
			Audit:    types.BoolDefault(false, resource.Metadata()),
		},
	}

	publicAccessAttr := resource.GetAttribute("publicly_accessible")
	broker.PublicAccess = publicAccessAttr.AsBoolValueOrDefault(false, resource)
	if logsBlock := resource.GetBlock("logs"); logsBlock.IsNotNil() {
		broker.Logging.Metadata = logsBlock.Metadata()
		auditAttr := logsBlock.GetAttribute("audit")
		broker.Logging.Audit = auditAttr.AsBoolValueOrDefault(false, logsBlock)
		generalAttr := logsBlock.GetAttribute("general")
		broker.Logging.General = generalAttr.AsBoolValueOrDefault(false, logsBlock)
	}

	return broker
}
