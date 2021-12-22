package database

import "github.com/aquasecurity/defsec/types"

type Database struct {
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

func (p SecurityAlertPolicy) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p SecurityAlertPolicy) GetRawValue() interface{} {
	return nil
}

func (s Server) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s Server) GetRawValue() interface{} {
	return nil
}

type ExtendedAuditingPolicy struct {
	RetentionInDays types.IntValue
}

type FirewallRule struct {
	StartIP types.StringValue
	EndIP   types.StringValue
}
