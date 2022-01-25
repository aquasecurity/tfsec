package sql

import (
	"strings"

	"github.com/aquasecurity/defsec/types"
)

type SQL struct {
	types.Metadata
	Instances []DatabaseInstance
}

const (
	DatabaseFamilyMySQL     = "MYSQL"
	DatabaseFamilyPostgres  = "POSTGRES"
	DatabaseFamilySQLServer = "SQLSERVER"
)

const (
	DatabaseVersionMySQL_5_6                 = "MYSQL_5_6"
	DatabaseVersionMySQL_5_7                 = "MYSQL_5_7"
	DatabaseVersionMySQL_8_0                 = "MYSQL_8_0"
	DatabaseVersionPostgres_9_6              = "POSTGRES_9_6"
	DatabaseVersionPostgres_10               = "POSTGRES_10"
	DatabaseVersionPostgres_11               = "POSTGRES_11"
	DatabaseVersionPostgres_12               = "POSTGRES_12"
	DatabaseVersionPostgres_13               = "POSTGRES_13"
	DatabaseVersionSQLServer_2017_STANDARD   = "SQLSERVER_2017_STANDARD"
	DatabaseVersionSQLServer_2017_ENTERPRISE = "SQLSERVER_2017_ENTERPRISE"
	DatabaseVersionSQLServer_2017_EXPRESS    = "SQLSERVER_2017_EXPRESS"
	DatabaseVersionSQLServer_2017_WEB        = "SQLSERVER_2017_WEB"
)

type DatabaseInstance struct {
	types.Metadata
	DatabaseVersion types.StringValue
	Settings        Settings
}

type Settings struct {
	types.Metadata
	Flags           Flags
	Backups         Backups
	IPConfiguration IPConfiguration
}
type Flags struct {
	types.Metadata
	LogTempFileSize                 types.IntValue
	LocalInFile                     types.BoolValue
	ContainedDatabaseAuthentication types.BoolValue
	CrossDBOwnershipChaining        types.BoolValue
	LogCheckpoints                  types.BoolValue
	LogConnections                  types.BoolValue
	LogDisconnections               types.BoolValue
	LogLockWaits                    types.BoolValue
	LogMinMessages                  types.StringValue // FATAL, PANIC, LOG, ERROR, WARN
	LogMinDurationStatement         types.IntValue
}

type Backups struct {
	types.Metadata
	Enabled types.BoolValue
}

type IPConfiguration struct {
	types.Metadata
	RequireTLS         types.BoolValue
	EnableIPv4         types.BoolValue
	AuthorizedNetworks []struct {
		Name types.StringValue
		CIDR types.StringValue
	}
}

func (i *DatabaseInstance) DatabaseFamily() string {
	return strings.Split(i.DatabaseVersion.Value(), "_")[0]
}

func (s *SQL) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SQL) GetRawValue() interface{} {
	return nil
}

func (d *DatabaseInstance) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DatabaseInstance) GetRawValue() interface{} {
	return nil
}

func (s *Settings) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Settings) GetRawValue() interface{} {
	return nil
}

func (f *Flags) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *Flags) GetRawValue() interface{} {
	return nil
}

func (b *Backups) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *Backups) GetRawValue() interface{} {
	return nil
}

func (i *IPConfiguration) GetMetadata() *types.Metadata {
	return &i.Metadata
}

func (i *IPConfiguration) GetRawValue() interface{} {
	return nil
}
