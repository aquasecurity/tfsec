package database

import "github.com/aquasecurity/defsec/types"

type Database struct {
	types.Metadata
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	Server
}

type MySQLServer struct {
	Server
}

type PostgreSQLServer struct {
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	LogCheckpoints       types.BoolValue
	ConnectionThrottling types.BoolValue
	LogConnections       types.BoolValue
}

type Server struct {
	types.Metadata
	EnableSSLEnforcement      types.BoolValue
	MinimumTLSVersion         types.StringValue
	EnablePublicNetworkAccess types.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	types.Metadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	types.Metadata
	EmailAddresses     []types.StringValue
	DisabledAlerts     []types.StringValue
	EmailAccountAdmins types.BoolValue
}

type ExtendedAuditingPolicy struct {
	types.Metadata
	RetentionInDays types.IntValue
}

type FirewallRule struct {
	types.Metadata
	StartIP types.StringValue
	EndIP   types.StringValue
}

func (d *Database) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *Database) GetRawValue() interface{} {
	return nil
}

func (s *Server) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Server) GetRawValue() interface{} {
	return nil
}

func (s *SecurityAlertPolicy) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SecurityAlertPolicy) GetRawValue() interface{} {
	return nil
}

func (e *ExtendedAuditingPolicy) GetMetadata() *types.Metadata {
	return &e.Metadata
}

func (e *ExtendedAuditingPolicy) GetRawValue() interface{} {
	return nil
}

func (f *FirewallRule) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *FirewallRule) GetRawValue() interface{} {
	return nil
}
