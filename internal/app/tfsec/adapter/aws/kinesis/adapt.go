package kinesis

import (
	"github.com/aquasecurity/defsec/provider/aws/kinesis"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) kinesis.Kinesis {
	return kinesis.Kinesis{
		Streams: adaptStreams(modules),
	}
}

func adaptStreams(modules block.Modules) []kinesis.Stream {
	var streams []kinesis.Stream
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kinesis_stream") {
			streams = append(streams, adaptStream(resource))
		}
	}
	return streams
}

func adaptStream(resource *block.Block) kinesis.Stream {
	encryptionTypeAttr := resource.GetAttribute("encryption_type")
	encryptionTypeVal := encryptionTypeAttr.AsStringValueOrDefault("NONE", resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	return kinesis.Stream{
		Metadata: *resource.GetMetadata(),
		Encryption: kinesis.Encryption{
			Type:     encryptionTypeVal,
			KMSKeyID: KMSKeyIDVal,
		},
	}
}
