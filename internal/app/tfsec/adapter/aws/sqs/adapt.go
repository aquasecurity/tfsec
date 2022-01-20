package sqs

import (
	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) sqs.SQS {
	return sqs.SQS{
		Queues: adaptQueues(modules),
	}
}

func adaptQueues(modules block.Modules) []sqs.Queue {
	var queues []sqs.Queue
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_sqs_queue") {
			queues = append(queues, adaptQueue(module, resource))
		}
	}
	return queues
}

func adaptQueue(module block.Module, resource block.Block) sqs.Queue {

	kmsKeyIdAttr := resource.GetAttribute("kms_master_key_id")
	kmsKeyIdVal := kmsKeyIdAttr.AsStringValueOrDefault("", resource)

	var policies []types.StringValue
	if attr := resource.GetAttribute("policy"); attr.IsString() {
		policies = append(policies, attr.AsStringValueOrDefault("", resource))
	}

	for _, policyBlock := range module.GetReferencingResources(resource, "aws_sqs_queue_policy", "queue_url") {
		if attr := policyBlock.GetAttribute("policy"); attr.IsString() {
			policies = append(policies, attr.AsStringValueOrDefault("", policyBlock))
		}
	}

	return sqs.Queue{
		Metadata: *resource.GetMetadata(),
		Encryption: sqs.Encryption{
			KMSKeyID: kmsKeyIdVal,
		},
		Policies: policies,
	}
}
