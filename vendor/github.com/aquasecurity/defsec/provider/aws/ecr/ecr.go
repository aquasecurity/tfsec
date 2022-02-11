package ecr

import (
	"github.com/aquasecurity/trivy-config-parsers/types"
)

type ECR struct {
	types.Metadata
	Repositories []Repository
}

type Repository struct {
	types.Metadata
	ImageScanning      ImageScanning
	ImageTagsImmutable types.BoolValue
	Policies           []types.StringValue
	Encryption         Encryption
}

type ImageScanning struct {
	types.Metadata
	ScanOnPush types.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	types.Metadata
	Type     types.StringValue
	KMSKeyID types.StringValue
}
