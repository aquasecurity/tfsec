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
			Metadata: *(b.GetMetadata()),
			Instance: ec2.Instance{
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
					launchConfig.RootBlockDevice.Encrypted = types.BoolDefault(true, *resource.GetMetadata())
					for i := 0; i < len(launchConfig.EBSBlockDevices); i++ {
						ebs := &launchConfig.EBSBlockDevices[i]
						ebs.Encrypted = types.BoolDefault(true, *resource.GetMetadata())
					}
				}
			}
			launchConfigurations = append(launchConfigurations, launchConfig)
		}
	}
	return launchConfigurations
}

func adaptLaunchConfiguration(resource *block.Block) autoscaling.LaunchConfiguration {
	nameVal := types.String("", *resource.GetMetadata())

	if resource.TypeLabel() == "aws_launch_configuration" {
		nameAttr := resource.GetAttribute("name")
		nameVal = nameAttr.AsStringValueOrDefault("", resource)
	}

	associatePublicIPAddressAttr := resource.GetAttribute("associate_public_ip_address")
	associatePublicIPAddressVal := associatePublicIPAddressAttr.AsBoolValueOrDefault(false, resource)

	rootEncryptedVal := types.BoolDefault(false, *resource.GetMetadata())
	var rootBlockDeviceBlock *block.Block
	rootBlockDevice := ec2.BlockDevice{
		Metadata:  *resource.GetMetadata(),
		Encrypted: rootEncryptedVal,
	}

	if resource.HasChild("root_block_device") {
		rootBlockDeviceBlock = resource.GetBlock("root_block_device")
		encryptedAttr := rootBlockDeviceBlock.GetAttribute("encrypted")
		rootEncryptedVal = encryptedAttr.AsBoolValueOrDefault(false, rootBlockDeviceBlock)
		rootBlockDevice = ec2.BlockDevice{
			Metadata:  rootBlockDevice.Metadata,
			Encrypted: rootEncryptedVal,
		}
	}

	var EBSBlockDevices []ec2.BlockDevice
	EBSBlockDevicesBlocks := resource.GetBlocks("ebs_block_device")
	for _, EBSBlockDevicesBlock := range EBSBlockDevicesBlocks {
		encryptedAttr := EBSBlockDevicesBlock.GetAttribute("encrypted")
		encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, EBSBlockDevicesBlock)
		EBSBlockDevices = append(EBSBlockDevices, ec2.BlockDevice{
			Metadata:  *EBSBlockDevicesBlock.GetMetadata(),
			Encrypted: encryptedVal,
		})
	}

	userDataVal := types.String("", *resource.GetMetadata())
	if resource.GetAttribute("user_data").IsNotNil() {
		userDataAttr := resource.GetAttribute("user_data")
		userDataVal = userDataAttr.AsStringValueOrDefault("", resource)
	} else if resource.GetAttribute("user_data_base64").IsNotNil() && resource.GetAttribute("user_data_base64").IsString() {
		userDataBase64Attr := resource.GetAttribute("user_data_base64")
		encoded, err := base64.StdEncoding.DecodeString(userDataBase64Attr.Value().AsString())
		if err == nil {
			userDataVal = types.String(string(encoded), *userDataBase64Attr.GetMetadata())
		}
	}

	return autoscaling.LaunchConfiguration{
		Metadata:          *resource.GetMetadata(),
		Name:              nameVal,
		AssociatePublicIP: associatePublicIPAddressVal,
		RootBlockDevice:   &rootBlockDevice,
		EBSBlockDevices:   EBSBlockDevices,
		MetadataOptions:   getMetadataOptions(resource),
		UserData:          userDataVal,
	}
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
