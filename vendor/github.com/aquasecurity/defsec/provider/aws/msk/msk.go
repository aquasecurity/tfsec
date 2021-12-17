package msk

import "github.com/aquasecurity/defsec/types"

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	EncryptionInTransit EncryptionInTransit
	Logging             Logging
}

const (
	ClientBrokerEncryptionTLS            = "TLS"
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	ClientBroker types.StringValue
}

type Logging struct {
	Broker BrokerLogging
}

type BrokerLogging struct {
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	Enabled types.BoolValue
}

type CloudwatchLogging struct {
	Enabled types.BoolValue
}

type FirehoseLogging struct {
	Enabled types.BoolValue
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}
