package autoscaling

import (
	"encoding/base64"

	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) autoscaling.Autoscaling {
	return autoscaling.Autoscaling{
		LaunchConfigurations: adaptLaunchConfigurations(modules),
		LaunchTemplates:      adaptLaunchTemplates(modules),
	}
}

func adaptLaunchTemplates(modules block.Modules) (templates []autoscaling.LaunchTemplate) {

	blocks := modules.GetResourcesByType("aws_launch_template")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := b.GetAttribute("user_data").AsStringValueOrDefault("", b)

		templates = append(templates, autoscaling.LaunchTemplate{
			Metadata: b.Metadata(),
			Instance: ec2.Instance{
				Metadata:        b.Metadata(),
				MetadataOptions: metadataOptions,
				UserData:        userData,
			},
		})
	}

	return templates
}

func adaptLaunchConfigurations(modules block.Modules) []autoscaling.LaunchConfiguration {
	var launchConfigurations []autoscaling.LaunchConfiguration

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_launch_configuration") {
			launchConfig := adaptLaunchConfiguration(resource)
			for _, resource := range module.GetResourcesByType("aws_ebs_encryption_by_default") {
				if resource.GetAttribute("enabled").NotEqual(false) {
					launchConfig.RootBlockDevice.Encrypted = types.BoolDefault(true, resource.Metadata())
					for i := 0; i < len(launchConfig.EBSBlockDevices); i++ {
						ebs := &launchConfig.EBSBlockDevices[i]
						ebs.Encrypted = types.BoolDefault(true, resource.Metadata())
					}
				}
			}
			launchConfigurations = append(launchConfigurations, launchConfig)
		}
	}
	return launchConfigurations
}

func adaptLaunchConfiguration(resource *block.Block) autoscaling.LaunchConfiguration {
	launchConfig := autoscaling.LaunchConfiguration{
		Metadata:          resource.Metadata(),
		Name:              types.StringDefault("", resource.Metadata()),
		AssociatePublicIP: resource.GetAttribute("associate_public_ip_address").AsBoolValueOrDefault(false, resource),
		RootBlockDevice: &ec2.BlockDevice{
			Metadata:  resource.Metadata(),
			Encrypted: types.BoolDefault(false, resource.Metadata()),
		},
		MetadataOptions: getMetadataOptions(resource),
		UserData:        types.StringDefault("", resource.Metadata()),
	}

	if resource.TypeLabel() == "aws_launch_configuration" {
		nameAttr := resource.GetAttribute("name")
		launchConfig.Name = nameAttr.AsStringValueOrDefault("", resource)
	}

	if rootBlockDeviceBlock := resource.GetBlock("root_block_device"); rootBlockDeviceBlock.IsNotNil() {
		encryptedAttr := rootBlockDeviceBlock.GetAttribute("encrypted")
		launchConfig.RootBlockDevice.Encrypted = encryptedAttr.AsBoolValueOrDefault(false, rootBlockDeviceBlock)
		launchConfig.RootBlockDevice.Metadata = rootBlockDeviceBlock.Metadata()
	}

	EBSBlockDevicesBlocks := resource.GetBlocks("ebs_block_device")
	for _, EBSBlockDevicesBlock := range EBSBlockDevicesBlocks {
		encryptedAttr := EBSBlockDevicesBlock.GetAttribute("encrypted")
		encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, EBSBlockDevicesBlock)
		launchConfig.EBSBlockDevices = append(launchConfig.EBSBlockDevices, ec2.BlockDevice{
			Metadata:  EBSBlockDevicesBlock.Metadata(),
			Encrypted: encryptedVal,
		})
	}

	if userDataAttr := resource.GetAttribute("user_data"); userDataAttr.IsNotNil() {
		launchConfig.UserData = userDataAttr.AsStringValueOrDefault("", resource)
	} else if userDataBase64Attr := resource.GetAttribute("user_data_base64"); userDataBase64Attr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(userDataBase64Attr.Value().AsString())
		if err == nil {
			launchConfig.UserData = types.String(string(encoded), userDataBase64Attr.Metadata())
		}
	}

	return launchConfig
}

func getMetadataOptions(b *block.Block) ec2.MetadataOptions {
	options := ec2.MetadataOptions{
		Metadata:     b.Metadata(),
		HttpTokens:   types.StringDefault("", b.Metadata()),
		HttpEndpoint: types.StringDefault("", b.Metadata()),
	}

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		options.Metadata = metadataOptions.Metadata()
		options.HttpTokens = metadataOptions.GetAttribute("http_tokens").AsStringValueOrDefault("", metadataOptions)
		options.HttpEndpoint = metadataOptions.GetAttribute("http_endpoint").AsStringValueOrDefault("", metadataOptions)
	}

	return options
}
