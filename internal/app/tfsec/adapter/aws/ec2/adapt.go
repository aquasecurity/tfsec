package ec2

import (
	"github.com/aquasecurity/defsec/definition"
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) ec2.EC2 {
	return ec2.EC2{
		Instances: getInstances(modules),
	}
}

func getInstances(modules block.Modules) []ec2.Instance {
	var instances []ec2.Instance

	blocks := modules.GetBlocksByTypeLabel("aws_instance")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := getUserData(b)

		instances = append(instances, ec2.Instance{
			Metadata:        definition.NewMetadata(b.Range()).WithReference(b.Reference()),
			MetadataOptions: metadataOptions,
			UserData:        userData,
		})
	}

	return instances
}

func getUserData(b block.Block) definition.StringValue {

	if userDataAttr := b.GetAttribute("user_data"); userDataAttr.IsNotNil() {
		return userDataAttr.AsStringValue()
	}
	return definition.EmptyStringValue(b.Range())
}

func getMetadataOptions(b block.Block) ec2.MetadataOptions {

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		metaOpts := ec2.MetadataOptions{
			Metadata: definition.NewMetadata(metadataOptions.Range()),
		}

		if httpTokens := metadataOptions.GetAttribute("http_tokens"); httpTokens.IsNotNil() {
			metaOpts.HttpTokens = httpTokens.AsStringValue()
		} else {
			metaOpts.HttpTokens = definition.EmptyStringValue(metadataOptions.Range())
		}

		if httpEndpoint := metadataOptions.GetAttribute("http_endpoint"); httpEndpoint.IsNotNil() {
			metaOpts.HttpEndpoint = httpEndpoint.AsStringValue()
		} else {
			metaOpts.HttpEndpoint = definition.EmptyStringValue(metadataOptions.Range())
		}
		return metaOpts
	}

	return ec2.MetadataOptions{
		Metadata:     definition.NewMetadata(b.Range()),
		HttpTokens:   definition.EmptyStringValue(b.Range()),
		HttpEndpoint: definition.EmptyStringValue(b.Range()),
	}
}
