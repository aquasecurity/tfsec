package ec2

import (
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/types"
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
			Metadata:        types.NewMetadata(b.Range(), b.Reference()),
			MetadataOptions: metadataOptions,
			UserData:        userData,
		})
	}

	return instances
}

func getUserData(b block.Block) types.StringValue {
	if userDataAttr := b.GetAttribute("user_data"); userDataAttr.IsNotNil() && userDataAttr.IsString() {
		return userDataAttr.AsStringValue(true)
	}
	return types.StringDefault(
		"",
		b.Range(),
		b.Reference(),
	)
}

func getMetadataOptions(b block.Block) ec2.MetadataOptions {

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		metaOpts := ec2.MetadataOptions{
			Metadata: types.NewMetadata(metadataOptions.Range(), metadataOptions.Reference()),
		}

		if httpTokens := metadataOptions.GetAttribute("http_tokens"); httpTokens.IsNotNil() {
			metaOpts.HttpTokens = httpTokens.AsStringValue(true)
		} else {
			metaOpts.HttpTokens = types.StringDefault("", metadataOptions.Range(), metadataOptions.Reference())
		}

		if httpEndpoint := metadataOptions.GetAttribute("http_endpoint"); httpEndpoint.IsNotNil() {
			metaOpts.HttpEndpoint = httpEndpoint.AsStringValue(true)
		} else {
			metaOpts.HttpEndpoint = types.StringDefault("", metadataOptions.Range(), metadataOptions.Reference())
		}
		return metaOpts
	}

	return ec2.MetadataOptions{
		Metadata:     types.NewMetadata(b.Range(), b.Reference()),
		HttpTokens:   types.StringDefault("", b.Range(), b.Reference()),
		HttpEndpoint: types.StringDefault("", b.Range(), b.Reference()),
	}
}
