package sqs

import (
	"encoding/json"

	"github.com/aquasecurity/defsec/adapters/terraform/aws/iam"

	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/google/uuid"
)

func Adapt(modules terraform.Modules) sqs.SQS {
	return sqs.SQS{
		Queues: (&adapter{
			modules: modules,
			queues:  make(map[string]sqs.Queue),
		}).adaptQueues(),
	}
}

type adapter struct {
	modules terraform.Modules
	queues  map[string]sqs.Queue
}

func (a *adapter) adaptQueues() []sqs.Queue {
	for _, resource := range a.modules.GetResourcesByType("aws_sqs_queue") {
		a.adaptQueue(resource)
	}

	for _, policyBlock := range a.modules.GetResourcesByType("aws_sqs_queue_policy") {

		policy := types.StringDefault("", policyBlock.GetMetadata())
		if attr := policyBlock.GetAttribute("policy"); attr.IsString() {
			policy = attr.AsStringValueOrDefault("", policyBlock)
		} else if refBlock, err := a.modules.GetReferencedBlock(attr, policyBlock); err == nil {
			if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
				if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
					if data, err := json.Marshal(doc.Document); err == nil {
						policy = types.String(string(data), refBlock.GetMetadata())
					}
				}
			}
		}

		if urlAttr := policyBlock.GetAttribute("queue_url"); urlAttr.IsNotNil() {
			if refBlock, err := a.modules.GetReferencedBlock(urlAttr, policyBlock); err == nil {
				if queue, ok := a.queues[refBlock.ID()]; ok {
					queue.Policies = append(queue.Policies, policy)
					a.queues[refBlock.ID()] = queue
					continue
				}
			}
		}

		a.queues[uuid.NewString()] = sqs.Queue{
			Metadata: types.NewUnmanagedMetadata(),
			Policies: []types.StringValue{policy},
		}
	}

	var queues []sqs.Queue
	for _, queue := range a.queues {
		queues = append(queues, queue)
	}
	return queues
}

func (a *adapter) adaptQueue(resource *terraform.Block) {

	kmsKeyIdAttr := resource.GetAttribute("kms_master_key_id")
	kmsKeyIdVal := kmsKeyIdAttr.AsStringValueOrDefault("", resource)

	var policies []types.StringValue
	if attr := resource.GetAttribute("policy"); attr.IsString() {
		policies = append(policies, attr.AsStringValueOrDefault("", resource))
	} else if refBlock, err := a.modules.GetReferencedBlock(attr, resource); err == nil {
		if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
			if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
				if data, err := json.Marshal(doc.Document); err == nil {
					policies = append(policies, types.String(string(data), refBlock.GetMetadata()))
				}
			}
		}
	}

	a.queues[resource.ID()] = sqs.Queue{
		Metadata: resource.GetMetadata(),
		Encryption: sqs.Encryption{
			Metadata: resource.GetMetadata(),
			KMSKeyID: kmsKeyIdVal,
		},
		Policies: policies,
	}
}
