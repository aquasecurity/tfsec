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

	instance := sql.DatabaseInstance{
		Metadata:        resource.Metadata(),
		DatabaseVersion: resource.GetAttribute("database_version").AsStringValueOrDefault("", resource),
		Settings: sql.Settings{
			Metadata: resource.Metadata(),
			Flags: sql.Flags{
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
			},
			Backups: sql.Backups{
				Metadata: resource.Metadata(),
				Enabled:  types.BoolDefault(false, *resource.GetMetadata()),
			},
			IPConfiguration: sql.IPConfiguration{
				Metadata:           resource.Metadata(),
				RequireTLS:         types.BoolDefault(false, *resource.GetMetadata()),
				EnableIPv4:         types.BoolDefault(true, *resource.GetMetadata()),
				AuthorizedNetworks: nil,
			},
		},
	}

	if settingsBlock := resource.GetBlock("settings"); settingsBlock.IsNotNil() {
		if blocks := settingsBlock.GetBlocks("database_flags"); len(blocks) > 0 {
			adaptFlags(blocks, &instance.Settings.Flags)
		}
		if backupBlock := settingsBlock.GetBlock("backup_configuration"); backupBlock.IsNotNil() {
			backupConfigEnabledAttr := backupBlock.GetAttribute("enabled")
			instance.Settings.Backups.Enabled = backupConfigEnabledAttr.AsBoolValueOrDefault(false, backupBlock)
		}
		if settingsBlock.HasChild("ip_configuration") {
			instance.Settings.IPConfiguration = adaptIPConfig(settingsBlock.GetBlock("ip_configuration"))
		}
	}
	return instance
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
		Metadata:           resource.Metadata(),
		RequireTLS:         tlsRequiredVal,
		EnableIPv4:         ipv4enabledVal,
		AuthorizedNetworks: authorizedNetworks,
	}
}
