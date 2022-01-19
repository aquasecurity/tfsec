package compute

import "github.com/aquasecurity/defsec/types"

type Instance struct {
	types.Metadata
	Name                        types.StringValue
	NetworkInterfaces           []NetworkInterface
	ShieldedVM                  ShieldedVMConfig
	ServiceAccount              ServiceAccount
	CanIPForward                types.BoolValue
	OSLoginEnabled              types.BoolValue
	EnableProjectSSHKeyBlocking types.BoolValue
	EnableSerialPort            types.BoolValue
	BootDisks                   []Disk
	AttachedDisks               []Disk
}

type ServiceAccount struct {
	types.Metadata
	Email  types.StringValue
	Scopes []types.StringValue
}

type NetworkInterface struct {
	types.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP types.BoolValue
	NATIP       types.StringValue
}

type ShieldedVMConfig struct {
	types.Metadata
	SecureBootEnabled          types.BoolValue
	IntegrityMonitoringEnabled types.BoolValue
	VTPMEnabled                types.BoolValue
}


func (i *Instance) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *Instance) GetRawValue() interface{} {
	return nil
}    


func (s *ServiceAccount) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *ServiceAccount) GetRawValue() interface{} {
	return nil
}    


func (n *NetworkInterface) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NetworkInterface) GetRawValue() interface{} {
	return nil
}    


func (s *ShieldedVMConfig) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *ShieldedVMConfig) GetRawValue() interface{} {
	return nil
}    
