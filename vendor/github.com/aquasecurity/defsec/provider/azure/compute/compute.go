package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	Name                   types.StringValue
	Region                 types.StringValue
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	CustomData types.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	DisablePasswordAuthentication types.BoolValue
}

type ManagedDisk struct {
	Encryption Encryption
}

type Encryption struct {
	Enabled types.BoolValue
}
