package kms

import "github.com/aquasecurity/defsec/types"

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	types.Metadata
	Usage           types.StringValue
	RotationEnabled types.BoolValue
}

func (c *Key) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Key) GetRawValue() interface{} {
	return nil
}
