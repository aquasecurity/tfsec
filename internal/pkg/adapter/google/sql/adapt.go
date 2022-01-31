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
		LogTempFileSize:                 types.IntDefault(-1, resource.Metadata()),
		LocalInFile:                     types.BoolDefault(false, resource.Metadata()),
		ContainedDatabaseAuthentication: types.BoolDefault(true, resource.Metadata()),
		CrossDBOwnershipChaining:        types.BoolDefault(true, resource.Metadata()),
		LogCheckpoints:                  types.BoolDefault(false, resource.Metadata()),
		LogConnections:                  types.BoolDefault(false, resource.Metadata()),
		LogDisconnections:               types.BoolDefault(false, resource.Metadata()),
		LogLockWaits:                    types.BoolDefault(false, resource.Metadata()),
		LogMinMessages:                  types.StringDefault("", resource.Metadata()),
		LogMinDurationStatement:         types.IntDefault(-1, resource.Metadata()),
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
		if blocks := settingsBlock.GetBlocks("database_flags"); len(blocks) > 0 {
			adaptFlags(blocks, &flags)
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

//nolint
func adaptFlags(resources block.Blocks, flags *sql.Flags) {
	for _, resource := range resources {

		nameAttr := resource.GetAttribute("name")
		valueAttr := resource.GetAttribute("value")

		if !nameAttr.IsString() || valueAttr.IsNil() {
			continue
		}

		switch nameAttr.Value().AsString() {
		case "log_temp_files":
			if logTempInt, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
				flags.LogTempFileSize = types.Int(logTempInt, nameAttr.Metadata())
			}
		case "log_min_messages":
			flags.LogMinMessages = valueAttr.AsStringValueOrDefault("", resource)
		case "log_min_duration_statement":
			if logMinDS, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
				flags.LogMinDurationStatement = types.Int(logMinDS, nameAttr.Metadata())
			}
		case "local_infile":
			flags.LocalInFile = types.Bool(valueAttr.Equals("on"), valueAttr.Metadata())
		case "log_checkpoints":
			flags.LogCheckpoints = types.Bool(valueAttr.Equals("on"), valueAttr.Metadata())
		case "log_connections":
			flags.LogConnections = types.Bool(valueAttr.Equals("on"), valueAttr.Metadata())
		case "log_disconnections":
			flags.LogDisconnections = types.Bool(valueAttr.Equals("on"), valueAttr.Metadata())
		case "log_lock_waits":
			flags.LogLockWaits = types.Bool(valueAttr.Equals("on"), valueAttr.Metadata())
		case "contained database authentication":
			flags.ContainedDatabaseAuthentication = types.Bool(valueAttr.Equals("on"), valueAttr.Metadata())
		case "cross db ownership chaining":
			flags.CrossDBOwnershipChaining = types.Bool(valueAttr.Equals("on"), valueAttr.Metadata())
		}
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
