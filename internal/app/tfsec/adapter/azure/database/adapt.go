package database

import (
	"github.com/aquasecurity/defsec/provider/azure/database"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) database.Database {
	return database.Database{
		MSSQLServers:      adaptMSSQLServers(modules),
		MariaDBServers:    adaptMariaDBServers(modules),
		MySQLServers:      adaptMySQLServers(modules),
		PostgreSQLServers: adaptPostgreSQLServers(modules),
	}
}

func adaptMSSQLServers(modules []block.Module) []database.MSSQLServer {
	var MSSQLServers []database.MSSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_sql_server") {
			MSSQLServers = append(MSSQLServers, adaptMSSQLServer(resource, module))
		}
		for _, resource := range module.GetResourcesByType("azurerm_mssql_server") {
			MSSQLServers = append(MSSQLServers, adaptMSSQLServer(resource, module))
		}
	}
	return MSSQLServers
}
func adaptMySQLServers(modules []block.Module) []database.MySQLServer {
	var mySQLServers []database.MySQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mysql_server") {
			mySQLServers = append(mySQLServers, adaptMySQLServer(resource, module))
		}
	}
	return mySQLServers
}

func adaptMariaDBServers(modules []block.Module) []database.MariaDBServer {
	var mariaDBServers []database.MariaDBServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mariadb_server") {
			mariaDBServers = append(mariaDBServers, adaptMariaDBServer(resource, module))
		}
	}
	return mariaDBServers
}

func adaptPostgreSQLServers(modules []block.Module) []database.PostgreSQLServer {
	var PostgreSQLServers []database.PostgreSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_postgresql_server") {
			PostgreSQLServers = append(PostgreSQLServers, adaptPostgreSQLServer(resource, module))
		}
	}
	return PostgreSQLServers
}

func adaptMSSQLServer(resource block.Block, module block.Module) database.MSSQLServer {
	minTLSVersionVal := types.StringDefault("", *resource.GetMetadata())
	publicAccessVal := types.BoolDefault(true, *resource.GetMetadata())
	enableSSLEnforcementVal := types.BoolDefault(false, *resource.GetMetadata())

	var auditingPolicies []database.ExtendedAuditingPolicy
	var alertPolicies []database.SecurityAlertPolicy
	var firewallRules []database.FirewallRule

	if resource.TypeLabel() == "azurerm_mssql_server" {
		minTLSVersionAttr := resource.GetAttribute("minimum_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("", resource)

		publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
		publicAccessVal = publicAccessAttr.AsBoolValueOrDefault(true, resource)

	}

	alertPolicyBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_security_alert_policy", "server_name")
	for _, alertBlock := range alertPolicyBlocks {
		alertPolicies = append(alertPolicies, adaptMSSQLSecurityAlertPolicy(alertBlock))
	}

	auditingPoliciesBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_extended_auditing_policy", "server_id")
	if resource.HasChild("extended_auditing_policy") {
		auditingPoliciesBlocks = append(auditingPoliciesBlocks, resource.GetBlocks("extended_auditing_policy")...)
	}

	databasesRes := module.GetReferencingResources(resource, "azurerm_mssql_database", "server_id")
	for _, databaseRes := range databasesRes {
		dbAuditingBlocks := module.GetReferencingResources(databaseRes, "azurerm_mssql_database_extended_auditing_policy", "database_id")
		auditingPoliciesBlocks = append(auditingPoliciesBlocks, dbAuditingBlocks...)
	}

	for _, auditBlock := range auditingPoliciesBlocks {
		auditingPolicies = append(auditingPolicies, adaptMSSQLExtendedAuditingPolicy(auditBlock))
	}

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_sql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database.MSSQLServer{
		Server: database.Server{
			Metadata:                  *resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
		ExtendedAuditingPolicies: auditingPolicies,
		SecurityAlertPolicies:    alertPolicies,
	}
}

func adaptMySQLServer(resource block.Block, module block.Module) database.MySQLServer {
	var firewallRules []database.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	minTLSVersionAttr := resource.GetAttribute("ssl_minimal_tls_version_enforced")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLSEnforcementDisabled", resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mysql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database.MySQLServer{
		Server: database.Server{
			Metadata:                  *resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
	}
}

func adaptMariaDBServer(resource block.Block, module block.Module) database.MariaDBServer {
	var firewallRules []database.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mariadb_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database.MariaDBServer{
		Server: database.Server{
			Metadata:                  *resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
	}
}

func adaptPostgreSQLServer(resource block.Block, module block.Module) database.PostgreSQLServer {
	var firewallRules []database.FirewallRule

	config := database.PostgresSQLConfig{
		LogCheckpoints:       types.BoolDefault(false, *resource.GetMetadata()),
		ConnectionThrottling: types.BoolDefault(false, *resource.GetMetadata()),
		LogConnections:       types.BoolDefault(false, *resource.GetMetadata()),
	}

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	minTLSVersionAttr := resource.GetAttribute("ssl_minimal_tls_version_enforced")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLSEnforcementDisabled", resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	configBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_configuration", "server_name")
	for _, configBlock := range configBlocks {
		config = adaptPostgreSQLConfig(configBlock)
	}

	return database.PostgreSQLServer{
		Server: database.Server{
			Metadata:                  *resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
		Config: config,
	}
}

func adaptPostgreSQLConfig(resource block.Block) database.PostgresSQLConfig {
	nameAttr := resource.GetAttribute("name")
	valAttr := resource.GetAttribute("value")

	logCheckpoints := types.BoolDefault(false, *resource.GetMetadata())
	connectionThrottling := types.BoolDefault(false, *resource.GetMetadata())
	logConnections := types.BoolDefault(false, *resource.GetMetadata())

	if valAttr.Equals("on") {
		if nameAttr.Equals("log_checkpoints") {
			logCheckpoints = types.Bool(true, *valAttr.GetMetadata())
		}
		if nameAttr.Equals("connection_throttling") {
			connectionThrottling = types.Bool(true, *valAttr.GetMetadata())
		}
		if nameAttr.Equals("log_connections") {
			logConnections = types.Bool(true, *valAttr.GetMetadata())
		}
	}

	return database.PostgresSQLConfig{
		LogCheckpoints:       logCheckpoints,
		ConnectionThrottling: connectionThrottling,
		LogConnections:       logConnections,
	}
}

func adaptMSSQLSecurityAlertPolicy(resource block.Block) database.SecurityAlertPolicy {
	var emailAddressesVal []types.StringValue
	var disabledAlertsVal []types.StringValue

	emailAddressesAttr := resource.GetAttribute("email_addresses")
	emailAddresses := emailAddressesAttr.ValueAsStrings()
	for _, email := range emailAddresses {
		emailAddressesVal = append(emailAddressesVal, types.String(email, *emailAddressesAttr.GetMetadata()))
	}

	disabledAlertsAttr := resource.GetAttribute("disabled_alerts")
	disabledAlerts := disabledAlertsAttr.ValueAsStrings()
	for _, alert := range disabledAlerts {
		disabledAlertsVal = append(disabledAlertsVal, types.String(alert, *disabledAlertsAttr.GetMetadata()))
	}

	emailAccountAdminsAttr := resource.GetAttribute("email_account_admins")
	emailAccountAdminsVal := emailAccountAdminsAttr.AsBoolValueOrDefault(false, resource)

	return database.SecurityAlertPolicy{
		Metadata:           *resource.GetMetadata(),
		EmailAddresses:     emailAddressesVal,
		DisabledAlerts:     disabledAlertsVal,
		EmailAccountAdmins: emailAccountAdminsVal,
	}
}

func adaptFirewallRule(resource block.Block) database.FirewallRule {
	startIPAttr := resource.GetAttribute("start_ip_address")
	startIPVal := startIPAttr.AsStringValueOrDefault("", resource)

	endIPAttr := resource.GetAttribute("end_ip_address")
	endIPVal := endIPAttr.AsStringValueOrDefault("", resource)

	return database.FirewallRule{
		StartIP: startIPVal,
		EndIP:   endIPVal,
	}
}

func adaptMSSQLExtendedAuditingPolicy(resource block.Block) database.ExtendedAuditingPolicy {
	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return database.ExtendedAuditingPolicy{
		RetentionInDays: retentionInDaysVal,
	}
}
