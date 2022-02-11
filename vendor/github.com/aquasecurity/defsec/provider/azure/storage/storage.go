package storage

import "github.com/aquasecurity/trivy-config-parsers/types"

type Storage struct {
	types.Metadata
	Accounts []Account
}

type Account struct {
	types.Metadata
	NetworkRules      []NetworkRule
	EnforceHTTPS      types.BoolValue
	Containers        []Container
	QueueProperties   QueueProperties
	MinimumTLSVersion types.StringValue
}

type QueueProperties struct {
	types.Metadata
	EnableLogging types.BoolValue
}

type NetworkRule struct {
	types.Metadata
	Bypass         []types.StringValue
	AllowByDefault types.BoolValue
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	types.Metadata
	PublicAccess types.StringValue
}
