package athena

import "github.com/aquasecurity/defsec/types"

type Athena struct {
	Databases  []Database
	Workgroups []Workgroup
}

type Database struct {
	types.Metadata
	Name       types.StringValue
	Encryption EncryptionConfiguration
}

type Workgroup struct {
	types.Metadata
	Name                 types.StringValue
	Encryption           EncryptionConfiguration
	EnforceConfiguration types.BoolValue
}

const (
	EncryptionTypeNone   = ""
	EncryptionTypeSSES3  = "SSE_S3"
	EncryptionTypeSSEKMS = "SSE_KMS"
	EncryptionTypeCSEKMS = "CSE_KMS"
)

type EncryptionConfiguration struct {
	Type types.StringValue
}

func (w *Workgroup) GetMetadata() *types.Metadata {
	return &w.Metadata
}

func (w *Workgroup) GetRawValue() interface{} {
	return nil
}

func (d *Database) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *Database) GetRawValue() interface{} {
	return nil
}
