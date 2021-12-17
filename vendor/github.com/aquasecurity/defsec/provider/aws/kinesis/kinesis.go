package kinesis

import "github.com/aquasecurity/defsec/types"

type Kinesis struct {
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
	Type     types.StringValue
	KMSKeyID types.StringValue
}

func (s *Stream) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Stream) GetRawValue() interface{} {
	return nil
}
