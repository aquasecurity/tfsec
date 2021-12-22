package mq

import "github.com/aquasecurity/defsec/types"

type MQ struct {
	Brokers []Broker
}

type Broker struct {
	types.Metadata
	PublicAccess types.BoolValue
	Logging      Logging
}

type Logging struct {
	General types.BoolValue
	Audit   types.BoolValue
}

func (c *Broker) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Broker) GetRawValue() interface{} {
	return nil
}
