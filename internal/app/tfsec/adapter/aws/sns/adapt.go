package sns

import (
	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) sns.SNS {
	return sns.SNS{
		Topics: adaptTopics(modules),
	}
}

func adaptTopics(modules []block.Module) []sns.Topic {
	var topics []sns.Topic
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_sns_topic") {
			topics = append(topics, adaptTopic(resource))
		}
	}
	return topics
}

func adaptTopic(resourceBlock block.Block) sns.Topic {
	return sns.Topic{
		Metadata: resourceBlock.Metadata(),
		Encryption: adaptEncryption(resourceBlock),
	}
}

func adaptEncryption(resourceBlock block.Block) sns.Encryption {
	return sns.Encryption{
		KMSKeyID: resourceBlock.GetAttribute("kms_master_key_id").AsStringValueOrDefault("alias/aws/sns", resourceBlock),
	}
}
