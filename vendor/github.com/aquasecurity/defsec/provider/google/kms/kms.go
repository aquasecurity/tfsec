package kms

import (
	"github.com/aquasecurity/defsec/types"
)

type KMS struct {
	types.Metadata
	KeyRings []KeyRing
}

type KeyRing struct {
	types.Metadata
	Keys []Key
}

type Key struct {
	types.Metadata
	RotationPeriodSeconds types.IntValue
}

func (k *KMS) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *KMS) GetRawValue() interface{} {
	return nil
}

func (k *KeyRing) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *KeyRing) GetRawValue() interface{} {
	return nil
}

func (k *Key) GetMetadata() *types.Metadata {
	return &k.Metadata
}

func (k *Key) GetRawValue() interface{} {
	return nil
}
