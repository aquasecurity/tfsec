package autoscaling

import (
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/types"
)

type Autoscaling struct {
	types.Metadata
	LaunchConfigurations []LaunchConfiguration
	LaunchTemplates      []LaunchTemplate
}

type LaunchConfiguration struct {
	types.Metadata
	Name              types.StringValue
	AssociatePublicIP types.BoolValue
	RootBlockDevice   *BlockDevice
	EBSBlockDevices   []BlockDevice
	MetadataOptions   ec2.MetadataOptions
	UserData          types.StringValue
}

type LaunchTemplate struct {
	types.Metadata
	ec2.Instance
}

type BlockDevice struct {
	types.Metadata
	Encrypted types.BoolValue
}

func (d *BlockDevice) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *BlockDevice) GetRawValue() interface{} {
	return nil
}

func (i *LaunchConfiguration) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}

func (d *LaunchConfiguration) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *LaunchConfiguration) GetRawValue() interface{} {
	return nil
}

func (d *LaunchTemplate) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *LaunchTemplate) GetRawValue() interface{} {
	return nil
}

func (a *Autoscaling) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *Autoscaling) GetRawValue() interface{} {
	return nil
}
