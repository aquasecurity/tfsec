package mq

import "github.com/aquasecurity/defsec/types"

type MQ struct {
	types.Metadata
	Brokers []Broker
}

type Broker struct {
	types.Metadata
	PublicAccess types.BoolValue
	Logging      Logging
}

type Logging struct {
	types.Metadata
	General types.BoolValue
	Audit   types.BoolValue
}

func (c *Broker) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Broker) GetRawValue() interface{} {
	return nil
}


func (m *MQ) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *MQ) GetRawValue() interface{} {
	return nil
}    


func (l *Logging) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *Logging) GetRawValue() interface{} {
	return nil
}    
