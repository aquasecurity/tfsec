package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	types.Metadata
	Name                   types.StringValue
	Region                 types.StringValue
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	types.Metadata
	CustomData types.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	types.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	types.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	types.Metadata
	DisablePasswordAuthentication types.BoolValue
}

type ManagedDisk struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	Enabled types.BoolValue
}


func (c *Compute) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Compute) GetRawValue() interface{} {
	return nil
}    


func (v *VirtualMachine) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *VirtualMachine) GetRawValue() interface{} {
	return nil
}    


func (l *LinuxVirtualMachine) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *LinuxVirtualMachine) GetRawValue() interface{} {
	return nil
}    


func (w *WindowsVirtualMachine) GetMetadata() *types.Metadata {
	return &w.Metadata
}

func (w *WindowsVirtualMachine) GetRawValue() interface{} {
	return nil
}    


func (o *OSProfileLinuxConfig) GetMetadata() *types.Metadata {
	return &o.Metadata
}

func (o *OSProfileLinuxConfig) GetRawValue() interface{} {
	return nil
}    


func (m *ManagedDisk) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *ManagedDisk) GetRawValue() interface{} {
	return nil
}    


func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}    
