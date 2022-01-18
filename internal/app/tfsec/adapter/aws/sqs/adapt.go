package sqs

import (
	"github.com/aquasecurity/defsec/provider/aws/sqs"

	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) sqs.SQS {
	return sqs.SQS{
		Queues: adaptQueues(modules),
	}
}

func adaptQueues(modules []block.Module) []sqs.Queue {
	var queues []sqs.Queue
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_sqs_queue", "aws_sqs_queue_policy") {
			queues = append(queues, adaptQueue(resource))
		}
	}
	return queues
}

func adaptQueue(resource block.Block) sqs.Queue {
	kmsKeyIdVal := types.StringDefault("", *resource.GetMetadata())
	var policies []types.StringValue

	if resource.TypeLabel() == "aws_sqs_queue" {
		kmsKeyIdAttr := resource.GetAttribute("kms_master_key_id")
		kmsKeyIdVal = kmsKeyIdAttr.AsStringValueOrDefault("", resource)
	}

	if resource.HasChild("policy") && resource.GetAttribute("policy").IsString() {
		policyAttr := resource.GetAttribute("policy")
		policies = append(policies, policyAttr.AsStringValueOrDefault("", resource))
	}

	return sqs.Queue{
		Metadata: *resource.GetMetadata(),
		Encryption: sqs.Encryption{
			KMSKeyID: kmsKeyIdVal,
		},
		Policies: policies,
	}
}
