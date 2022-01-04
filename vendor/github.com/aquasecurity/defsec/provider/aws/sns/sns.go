package sns

import "github.com/aquasecurity/defsec/types"

type SNS struct {
	Topics []Topic
}

type Topic struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	KMSKeyID types.StringValue
}

func (v *Topic) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Topic) GetRawValue() interface{} {
	return nil
}
