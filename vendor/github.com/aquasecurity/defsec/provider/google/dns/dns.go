package dns

import "github.com/aquasecurity/defsec/types"

type DNS struct {
	types.Metadata
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	types.Metadata
	DNSSec DNSSec
}

type DNSSec struct {
	types.Metadata
	Enabled         types.BoolValue
	DefaultKeySpecs KeySpecs
}

type KeySpecs struct {
	types.Metadata
	KeySigningKey  Key
	ZoneSigningKey Key
}

type Key struct {
	types.Metadata
	Algorithm types.StringValue
}


func (d *DNS) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DNS) GetRawValue() interface{} {
	return nil
}    


func (m *ManagedZone) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *ManagedZone) GetRawValue() interface{} {
	return nil
}    


func (d *DNSSec) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DNSSec) GetRawValue() interface{} {
	return nil
}    


func (k *KeySpecs) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *KeySpecs) GetRawValue() interface{} {
	return nil
}    


func (k *Key) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *Key) GetRawValue() interface{} {
	return nil
}    
