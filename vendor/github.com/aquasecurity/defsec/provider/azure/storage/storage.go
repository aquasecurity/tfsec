package storage

import "github.com/aquasecurity/defsec/types"

type Storage struct {
	Accounts []Account
}

type Account struct {
	NetworkRules      []NetworkRule
	EnforceHTTPS      types.BoolValue
	Containers        []Container
	QueueProperties   QueueProperties
	MinimumTLSVersion types.StringValue
}

type QueueProperties struct {
	EnableLogging types.BoolValue
}

type NetworkRule struct {
	types.Metadata
	Bypass         []types.StringValue
	AllowByDefault types.BoolValue
}

func (r NetworkRule) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r NetworkRule) GetRawValue() interface{} {
	return nil
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	PublicAccess types.StringValue
}
