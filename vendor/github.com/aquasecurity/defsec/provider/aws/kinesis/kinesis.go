package kinesis

import "github.com/aquasecurity/defsec/types"

type Kinesis struct {
	types.Metadata
	Streams []Stream
}

type Stream struct {
	types.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	types.Metadata
	Type     types.StringValue
	KMSKeyID types.StringValue
}

func (s *Stream) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Stream) GetRawValue() interface{} {
	return nil
}

func (k *Kinesis) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *Kinesis) GetRawValue() interface{} {
	return nil
}

func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}
