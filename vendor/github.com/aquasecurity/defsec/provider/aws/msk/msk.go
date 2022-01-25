package msk

import "github.com/aquasecurity/defsec/types"

type MSK struct {
	types.Metadata
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
	types.Metadata
	ClientBroker types.StringValue
}

type Logging struct {
	types.Metadata
	Broker BrokerLogging
}

type BrokerLogging struct {
	types.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	types.Metadata
	Enabled types.BoolValue
}

type CloudwatchLogging struct {
	types.Metadata
	Enabled types.BoolValue
}

type FirehoseLogging struct {
	types.Metadata
	Enabled types.BoolValue
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}


func (m *MSK) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *MSK) GetRawValue() interface{} {
	return nil
}    


func (e *EncryptionInTransit) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *EncryptionInTransit) GetRawValue() interface{} {
	return nil
}    


func (l *Logging) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *Logging) GetRawValue() interface{} {
	return nil
}    


func (b *BrokerLogging) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *BrokerLogging) GetRawValue() interface{} {
	return nil
}    


func (s *S3Logging) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *S3Logging) GetRawValue() interface{} {
	return nil
}    


func (c *CloudwatchLogging) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *CloudwatchLogging) GetRawValue() interface{} {
	return nil
}    


func (f *FirehoseLogging) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *FirehoseLogging) GetRawValue() interface{} {
	return nil
}    
