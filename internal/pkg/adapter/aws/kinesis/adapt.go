package kinesis

import (
	"github.com/aquasecurity/defsec/provider/aws/kinesis"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
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

	stream := kinesis.Stream{
		Metadata: resource.Metadata(),
		Encryption: kinesis.Encryption{
			Metadata: resource.Metadata(),
			Type:     types.StringDefault("NONE", resource.Metadata()),
			KMSKeyID: types.StringDefault("", resource.Metadata()),
		},
	}

	encryptionTypeAttr := resource.GetAttribute("encryption_type")
	stream.Encryption.Type = encryptionTypeAttr.AsStringValueOrDefault("NONE", resource)
	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	stream.Encryption.KMSKeyID = KMSKeyIDAttr.AsStringValueOrDefault("", resource)
	return stream
}
