package sql

import (
	"strconv"

	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) sql.SQL {
	return sql.SQL{
		Instances: adaptInstances(modules),
	}
}

func adaptInstances(modules block.Modules) []sql.DatabaseInstance {
	var instances []sql.DatabaseInstance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_sql_database_instance") {
			instances = append(instances, adaptInstance(resource))
		}
	}
	return instances
}

func adaptInstance(resource *block.Block) sql.DatabaseInstance {

	backupConfigEnabledVal := types.BoolDefault(false, *resource.GetMetadata())

	flags := sql.Flags{
		LogTempFileSize:                 types.IntDefault(-1, *resource.GetMetadata()),
		LocalInFile:                     types.BoolDefault(false, *resource.GetMetadata()),
		ContainedDatabaseAuthentication: types.BoolDefault(true, *resource.GetMetadata()),
		CrossDBOwnershipChaining:        types.BoolDefault(true, *resource.GetMetadata()),
		LogCheckpoints:                  types.BoolDefault(false, *resource.GetMetadata()),
		LogConnections:                  types.BoolDefault(false, *resource.GetMetadata()),
		LogDisconnections:               types.BoolDefault(false, *resource.GetMetadata()),
		LogLockWaits:                    types.BoolDefault(false, *resource.GetMetadata()),
		LogMinMessages:                  types.StringDefault("", *resource.GetMetadata()),
		LogMinDurationStatement:         types.IntDefault(-1, *resource.GetMetadata()),
	}

	ipConfig := sql.IPConfiguration{
		RequireTLS: types.BoolDefault(false, *resource.GetMetadata()),
		EnableIPv4: types.BoolDefault(true, *resource.GetMetadata()),
		AuthorizedNetworks: []struct {
			Name types.StringValue
			CIDR types.StringValue
		}{},
	}

	dbVersionVal := resource.GetAttribute("database_version").AsStringValueOrDefault("", resource)

	if resource.HasChild("settings") {
		settingsBlock := resource.GetBlock("settings")
		if settingsBlock.HasChild("database_flags") {
			flags = adaptFlags(settingsBlock.GetBlock("database_flags"))
		}
		if settingsBlock.HasChild("backup_configuration") {
			backupConfigEnabledAttr := settingsBlock.GetBlock("backup_configuration").GetAttribute("enabled")
			backupConfigEnabledVal = backupConfigEnabledAttr.AsBoolValueOrDefault(false, settingsBlock.GetBlock("backup_configuration"))
		}
		if settingsBlock.HasChild("ip_configuration") {
			ipConfig = adaptIPConfig(settingsBlock.GetBlock("ip_configuration"))
		}
	}
	return sql.DatabaseInstance{
		Metadata:        resource.Metadata(),
		DatabaseVersion: dbVersionVal,
		Settings: sql.Settings{
			Flags: flags,
			Backups: sql.Backups{
				Enabled: backupConfigEnabledVal,
			},
			IPConfiguration: ipConfig,
		},
	}
}

func adaptFlags(resource *block.Block) sql.Flags {
	nameAttr := resource.GetAttribute("name")
	valueAttr := resource.GetAttribute("value")

	logTempFileSize := types.IntDefault(-1, *resource.GetMetadata())
	localInFile := types.BoolDefault(false, *resource.GetMetadata())
	containedDbAuth := types.BoolDefault(true, *resource.GetMetadata())
	crossDbOwnershipChaining := types.BoolDefault(true, *resource.GetMetadata())
	logCheckpoints := types.BoolDefault(false, *resource.GetMetadata())
	logConnections := types.BoolDefault(false, *resource.GetMetadata())
	logDisconnections := types.BoolDefault(false, *resource.GetMetadata())
	logLockWaits := types.BoolDefault(false, *resource.GetMetadata())
	logMinMsgs := types.StringDefault("", *resource.GetMetadata())
	logMinDurationStatement := types.IntDefault(-1, *resource.GetMetadata())

	if nameAttr.Equals("log_temp_files", block.IgnoreCase) && valueAttr.IsNotNil() {
		if logTempInt, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
			logTempFileSize = types.Int(logTempInt, nameAttr.Metadata())
		}
	}

	if valueAttr.Equals("on", block.IgnoreCase) {
		localInFile = types.Bool(nameAttr.Equals("local_infile", block.IgnoreCase), *resource.GetMetadata())
		logCheckpoints = types.Bool(nameAttr.Equals("log_checkpoints", block.IgnoreCase), *resource.GetMetadata())
		logConnections = types.Bool(nameAttr.Equals("log_connections", block.IgnoreCase), *resource.GetMetadata())
		logDisconnections = types.Bool(nameAttr.Equals("log_disconnections", block.IgnoreCase), *resource.GetMetadata())
		logLockWaits = types.Bool(nameAttr.Equals("log_lock_waits", block.IgnoreCase), *resource.GetMetadata())

	} else if valueAttr.Equals("off", block.IgnoreCase) {
		containedDbAuth = types.Bool(!nameAttr.Equals("contained database authentication", block.IgnoreCase), *resource.GetMetadata())
		crossDbOwnershipChaining = types.Bool(!nameAttr.Equals("cross db ownership chaining", block.IgnoreCase), *resource.GetMetadata())
	}

	if nameAttr.Equals("log_min_messages", block.IgnoreCase) {
		logMinMsgs = valueAttr.AsStringValueOrDefault("", resource)
	}

	if nameAttr.Equals("log_min_duration_statement", block.IgnoreCase) && valueAttr.IsNotNil() {
		if logMinDS, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
			logMinDurationStatement = types.Int(logMinDS, nameAttr.Metadata())
		}
	}

	return sql.Flags{
		LogTempFileSize:                 logTempFileSize,
		LocalInFile:                     localInFile,
		ContainedDatabaseAuthentication: containedDbAuth,
		CrossDBOwnershipChaining:        crossDbOwnershipChaining,
		LogCheckpoints:                  logCheckpoints,
		LogConnections:                  logConnections,
		LogDisconnections:               logDisconnections,
		LogLockWaits:                    logLockWaits,
		LogMinMessages:                  logMinMsgs,
		LogMinDurationStatement:         logMinDurationStatement,
	}
}

func adaptIPConfig(resource *block.Block) sql.IPConfiguration {
	var authorizedNetworks []struct {
		Name types.StringValue
		CIDR types.StringValue
	}

	tlsRequiredAttr := resource.GetAttribute("require_ssl")
	tlsRequiredVal := tlsRequiredAttr.AsBoolValueOrDefault(false, resource)

	ipv4enabledAttr := resource.GetAttribute("ipv4_enabled")
	ipv4enabledVal := ipv4enabledAttr.AsBoolValueOrDefault(true, resource)

	authNetworksBlocks := resource.GetBlocks("authorized_networks")
	for _, authBlock := range authNetworksBlocks {
		nameVal := authBlock.GetAttribute("name").AsStringValueOrDefault("", authBlock)
		cidrVal := authBlock.GetAttribute("value").AsStringValueOrDefault("", authBlock)

		authorizedNetworks = append(authorizedNetworks, struct {
			Name types.StringValue
			CIDR types.StringValue
		}{
			Name: nameVal,
			CIDR: cidrVal,
		})
	}

	return sql.IPConfiguration{
		RequireTLS:         tlsRequiredVal,
		EnableIPv4:         ipv4enabledVal,
		AuthorizedNetworks: authorizedNetworks,
	}
}
