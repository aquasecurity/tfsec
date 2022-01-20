package ec2

import (
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) ec2.EC2 {
	return ec2.EC2{
		Instances: getInstances(modules),
	}
}

func getInstances(modules block.Modules) []ec2.Instance {
	var instances []ec2.Instance

	blocks := modules.GetResourcesByType("aws_instance")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := b.GetAttribute("user_data").AsStringValueOrDefault("", b)

		instances = append(instances, ec2.Instance{
			Metadata:        *(b.GetMetadata()),
			MetadataOptions: metadataOptions,
			UserData:        userData,
		})
	}

	return instances
}

func getMetadataOptions(b block.Block) ec2.MetadataOptions {

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		metaOpts := ec2.MetadataOptions{
			Metadata: metadataOptions.Metadata(),
		}

		metaOpts.HttpTokens = metadataOptions.GetAttribute("http_tokens").AsStringValueOrDefault("", metadataOptions)
		metaOpts.HttpEndpoint = metadataOptions.GetAttribute("http_endpoint").AsStringValueOrDefault("", metadataOptions)
		return metaOpts
	}

	return ec2.MetadataOptions{
		Metadata:     b.Metadata(),
		HttpTokens:   types.StringDefault("", b.Metadata()),
		HttpEndpoint: types.StringDefault("", b.Metadata()),
	}
}
