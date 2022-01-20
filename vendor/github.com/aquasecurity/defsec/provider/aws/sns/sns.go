package sns

import "github.com/aquasecurity/defsec/types"

type SNS struct {
	types.Metadata
	Topics []Topic
}

type Topic struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}

func (v *Topic) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Topic) GetRawValue() interface{} {
	return nil
}


func (s *SNS) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SNS) GetRawValue() interface{} {
	return nil
}    


func (e *Encryption) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *Encryption) GetRawValue() interface{} {
	return nil
}    
