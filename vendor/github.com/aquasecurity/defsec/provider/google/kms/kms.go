package kms

import (
	"github.com/aquasecurity/defsec/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	Keys []Key
}

type Key struct {
	RotationPeriodSeconds types.IntValue
}
