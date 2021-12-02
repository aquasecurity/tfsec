package sqs

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	types.Metadata
	Encryption Encryption
	Policy     iam.PolicyDocument
}

type Encryption struct {
	KMSKeyID types.StringValue
}

func (v *Queue) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Queue) GetRawValue() interface{} {
	return nil
}
