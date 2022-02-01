package ec2

import (
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
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

		instance := ec2.Instance{
			Metadata:        b.Metadata(),
			MetadataOptions: metadataOptions,
			UserData:        userData,
			RootBlockDevice: &ec2.BlockDevice{
				Metadata:  b.Metadata(),
				Encrypted: types.BoolDefault(false, b.Metadata()),
			},
		}

		if rootBlockDevice := b.GetBlock("root_block_device"); rootBlockDevice.IsNotNil() {
			instance.RootBlockDevice.Metadata = rootBlockDevice.Metadata()
			instance.RootBlockDevice.Encrypted = rootBlockDevice.GetAttribute("encrypted").AsBoolValueOrDefault(false, b)
		}

		for _, ebsBlock := range b.GetBlocks("ebs_block_device") {
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, ec2.BlockDevice{
				Metadata:  ebsBlock.Metadata(),
				Encrypted: ebsBlock.GetAttribute("encrypted").AsBoolValueOrDefault(false, b),
			})
		}

		for _, resource := range modules.GetResourcesByType("aws_ebs_encryption_by_default") {
			if resource.GetAttribute("enabled").NotEqual(false) {
				instance.RootBlockDevice.Encrypted = types.BoolDefault(true, resource.Metadata())
				for i := 0; i < len(instance.EBSBlockDevices); i++ {
					ebs := &instance.EBSBlockDevices[i]
					ebs.Encrypted = types.BoolDefault(true, resource.Metadata())
				}
			}
		}

		instances = append(instances, instance)
	}

	return instances
}

func getMetadataOptions(b *block.Block) ec2.MetadataOptions {

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
