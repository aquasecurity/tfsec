package ecr

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
)

type ECR struct {
	Repositories []Repository
}

type Repository struct {
	types.Metadata
	ImageScanning      ImageScanning
	ImageTagsImmutable types.BoolValue
	Policy             iam.PolicyDocument
	Encryption         Encryption
}

type ImageScanning struct {
	ScanOnPush types.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	Type     types.StringValue
	KMSKeyID types.StringValue
}

func (c *Repository) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Repository) GetRawValue() interface{} {
	return nil
}
