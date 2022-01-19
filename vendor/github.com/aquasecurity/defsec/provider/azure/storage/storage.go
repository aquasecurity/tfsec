package storage

import "github.com/aquasecurity/defsec/types"

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

func (s *Storage) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Storage) GetRawValue() interface{} {
	return nil
}

func (a *Account) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *Account) GetRawValue() interface{} {
	return nil
}

func (q *QueueProperties) GetMetadata() *types.Metadata {
	return &q.Metadata
}

func (q *QueueProperties) GetRawValue() interface{} {
	return nil
}

func (n *NetworkRule) GetMetadata() *types.Metadata {
	return &n.Metadata
}

func (n *NetworkRule) GetRawValue() interface{} {
	return nil
}

func (c *Container) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Container) GetRawValue() interface{} {
	return nil
}
