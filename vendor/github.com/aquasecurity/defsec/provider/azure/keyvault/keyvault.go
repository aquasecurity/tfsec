package keyvault

import (
	"github.com/aquasecurity/defsec/types"
)

type KeyVault struct {
	types.Metadata
	Vaults []Vault
}

type Vault struct {
	types.Metadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   types.BoolValue
	SoftDeleteRetentionDays types.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	types.Metadata
	DefaultAction types.StringValue
}

type Key struct {
	types.Metadata
	ExpiryDate types.TimeValue
}

type Secret struct {
	types.Metadata
	ContentType types.StringValue
	ExpiryDate  types.TimeValue
}

func (k *KeyVault) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *KeyVault) GetRawValue() interface{} {
	return nil
}

func (v *Vault) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Vault) GetRawValue() interface{} {
	return nil
}

func (n *NetworkACLs) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NetworkACLs) GetRawValue() interface{} {
	return nil
}

func (k *Key) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *Key) GetRawValue() interface{} {
	return nil
}

func (s *Secret) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Secret) GetRawValue() interface{} {
	return nil
}
