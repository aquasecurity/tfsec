package sqs

import (
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/adapters/terraform/aws/iam"
	iamp "github.com/aquasecurity/defsec/provider/aws/iam"

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

		var policy iamp.Policy
		policy.Metadata = policyBlock.GetMetadata()
		if attr := policyBlock.GetAttribute("policy"); attr.IsString() {
			parsed, err := iamgo.ParseString(attr.Value().AsString())
			if err != nil {
				continue
			}
			policy.Document.Parsed = *parsed
			policy.Document.Metadata = attr.GetMetadata()
		} else if refBlock, err := a.modules.GetReferencedBlock(attr, policyBlock); err == nil {
			if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
				if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
					policy.Document.Parsed = doc.Document
					policy.Document.Metadata = doc.Source.GetMetadata()
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
			Policies: []iamp.Policy{policy},
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

	var policies []iamp.Policy
	if attr := resource.GetAttribute("policy"); attr.IsString() {
		var policy iamp.Policy
		parsed, err := iamgo.ParseString(attr.Value().AsString())
		if err == nil {
			policy.Document.Parsed = *parsed
			policy.Document.Metadata = attr.GetMetadata()
			policies = append(policies, policy)
		}
	} else if refBlock, err := a.modules.GetReferencedBlock(attr, resource); err == nil {
		if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
			if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
				var policy iamp.Policy
				policy.Document.Parsed = doc.Document
				policy.Document.Metadata = doc.Source.GetMetadata()
				policies = append(policies, policy)
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
