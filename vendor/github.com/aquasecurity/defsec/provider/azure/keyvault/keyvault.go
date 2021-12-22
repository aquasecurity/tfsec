package keyvault

import (
	"github.com/aquasecurity/defsec/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	Secrets               []Secret
	Keys                  []Key
	EnablePurgeProtection types.BoolValue
	NetworkACLs           NetworkACLs
}

type NetworkACLs struct {
	DefaultAction types.StringValue
}

type Key struct {
	ExpiryDate types.TimeValue
}

type Secret struct {
	ContentType types.StringValue
	ExpiryDate  types.TimeValue
}
