package elasticsearch

import "github.com/aquasecurity/defsec/types"

type Elasticsearch struct {
	types.Metadata
	Domains []Domain
}

type Domain struct {
	types.Metadata
	DomainName        types.StringValue
	LogPublishing     LogPublishing
	TransitEncryption TransitEncryption
	AtRestEncryption  AtRestEncryption
	Endpoint          Endpoint
}

type Endpoint struct {
	types.Metadata
	EnforceHTTPS types.BoolValue
	TLSPolicy    types.StringValue
}

type LogPublishing struct {
	types.Metadata
	AuditEnabled types.BoolValue
}

type TransitEncryption struct {
	types.Metadata
	Enabled types.BoolValue
}

type AtRestEncryption struct {
	types.Metadata
	Enabled types.BoolValue
}

func (c *Domain) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Domain) GetRawValue() interface{} {
	return nil
}

func (e *Elasticsearch) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Elasticsearch) GetRawValue() interface{} {
	return nil
}

func (e *Endpoint) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Endpoint) GetRawValue() interface{} {
	return nil
}

func (l *LogPublishing) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *LogPublishing) GetRawValue() interface{} {
	return nil
}

func (t *TransitEncryption) GetMetadata() *types.Metadata {
	return &t.Metadata
}

func (t *TransitEncryption) GetRawValue() interface{} {
	return nil
}

func (a *AtRestEncryption) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *AtRestEncryption) GetRawValue() interface{} {
	return nil
}
