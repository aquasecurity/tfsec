package elasticsearch

import "github.com/aquasecurity/defsec/types"

type Elasticsearch struct {
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
	EnforceHTTPS types.BoolValue
	TLSPolicy    types.StringValue
}

type LogPublishing struct {
	AuditEnabled types.BoolValue
}

type TransitEncryption struct {
	Enabled types.BoolValue
}

type AtRestEncryption struct {
	Enabled types.BoolValue
}

func (c *Domain) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Domain) GetRawValue() interface{} {
	return nil
}
