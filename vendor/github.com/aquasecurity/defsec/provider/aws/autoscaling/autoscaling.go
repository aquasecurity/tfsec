package autoscaling

import "github.com/aquasecurity/defsec/types"

type Autoscaling struct {
	LaunchConfigurations []LaunchConfiguration
}

type LaunchConfiguration struct {
	types.Metadata
	Name              types.StringValue
	AssociatePublicIP types.BoolValue
	RootBlockDevice   *BlockDevice
	EBSBlockDevices   []BlockDevice
	UserData          types.StringValue
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

func (d *LaunchConfiguration) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *LaunchConfiguration) GetRawValue() interface{} {
	return nil
}
