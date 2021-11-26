---
title: Azure Checks
permalink: /docs/azure/home/
has_children: true
has_toc: false
---

The included Azure checks are listed below. For more information about each check, see the link provided.

| Checks |
|:------------|
|[azure-appservice-account-identity-registered](/docs/azure/appservice/account-identity-registered)<br>Web App has registration with AD enabled|
|[azure-appservice-authentication-enabled](/docs/azure/appservice/authentication-enabled)<br>App Service authentication is activated|
|[azure-appservice-detailed-error-messages-enabled](/docs/azure/appservice/detailed-error-messages-enabled)<br>App service disables detailed error messages|
|[azure-appservice-dotnet-framework-version](/docs/azure/appservice/dotnet-framework-version)<br>Azure App Service Web app does not use the latest .Net Core version|
|[azure-appservice-enable-http2](/docs/azure/appservice/enable-http2)<br>Web App uses the latest HTTP version|
|[azure-appservice-enable-https-only](/docs/azure/appservice/enable-https-only)<br>Ensure App Service can only be accessed via HTTPS. The default is false|
|[azure-appservice-failed-request-tracing-enabled](/docs/azure/appservice/failed-request-tracing-enabled)<br>App service does not enable failed request tracing|
|[azure-appservice-ftp-deployments-disabled](/docs/azure/appservice/ftp-deployments-disabled)<br>Ensure FTP Deployments are disabled|
|[azure-appservice-http-logs-enabled](/docs/azure/appservice/http-logs-enabled)<br>App service does not enable HTTP logging|
|[azure-appservice-php-version](/docs/azure/appservice/php-version)<br>Azure App Service Web app does not use the latest PHP version|
|[azure-appservice-python-version](/docs/azure/appservice/python-version)<br>Azure App Service Web app does not use the latest Python version|
|[azure-appservice-require-client-cert](/docs/azure/appservice/require-client-cert)<br>Web App accepts incoming client certificate|
|[azure-appservice-use-secure-tls-policy](/docs/azure/appservice/use-secure-tls-policy)<br>Web App uses latest TLS version|
|[azure-authorization-limit-role-actions](/docs/azure/authorization/limit-role-actions)<br>Roles limited to the required actions|
|[azure-compute-disable-password-authentication](/docs/azure/compute/disable-password-authentication)<br>Password authentication should be disabled on Azure virtual machines|
|[azure-compute-enable-disk-encryption](/docs/azure/compute/enable-disk-encryption)<br>Enable disk encryption on managed disk|
|[azure-compute-no-secrets-in-custom-data](/docs/azure/compute/no-secrets-in-custom-data)<br>Ensure that no sensitive credentials are exposed in VM custom_data|
|[azure-compute-ssh-authentication](/docs/azure/compute/ssh-authentication)<br>Password authentication in use instead of SSH keys.|
|[azure-container-configured-network-policy](/docs/azure/container/configured-network-policy)<br>Ensure AKS cluster has Network Policy configured|
|[azure-container-limit-authorized-ips](/docs/azure/container/limit-authorized-ips)<br>Ensure AKS has an API Server Authorized IP Ranges enabled|
|[azure-container-logging](/docs/azure/container/logging)<br>Ensure AKS logging to Azure Monitoring is Configured|
|[azure-container-use-rbac-permissions](/docs/azure/container/use-rbac-permissions)<br>Ensure RBAC is enabled on AKS clusters|
|[azure-database-enable-audit](/docs/azure/database/enable-audit)<br>Auditing should be enabled on Azure SQL Databases|
|[azure-database-enable-ssl-enforcement](/docs/azure/database/enable-ssl-enforcement)<br>SSL should be enforced on database connections where applicable|
|[azure-database-mysql-threat-detection-enabled](/docs/azure/database/mysql-threat-detection-enabled)<br>Ensure databases are not publicly accessible|
|[azure-database-no-public-access](/docs/azure/database/no-public-access)<br>Ensure databases are not publicly accessible|
|[azure-database-no-public-firewall-access](/docs/azure/database/no-public-firewall-access)<br>Ensure database firewalls do not permit public access|
|[azure-database-postgres-configuration-log-checkpoints](/docs/azure/database/postgres-configuration-log-checkpoints)<br>Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server|
|[azure-database-postgres-configuration-log-connection-throttling](/docs/azure/database/postgres-configuration-log-connection-throttling)<br>Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server|
|[azure-database-postgres-configuration-log-connections](/docs/azure/database/postgres-configuration-log-connections)<br>Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server|
|[azure-database-retention-period-set](/docs/azure/database/retention-period-set)<br>Database auditing rentention period should be longer than 90 days|
|[azure-database-secure-tls-policy](/docs/azure/database/secure-tls-policy)<br>Databases should have the minimum TLS set for connections|
|[azure-datafactory-no-public-access](/docs/azure/datafactory/no-public-access)<br>Data Factory should have public access disabled, the default is enabled.|
|[azure-datalake-enable-at-rest-encryption](/docs/azure/datalake/enable-at-rest-encryption)<br>Unencrypted data lake storage.|
|[azure-functionapp-authentication-enabled](/docs/azure/functionapp/authentication-enabled)<br>Function App authentication is activated|
|[azure-functionapp-enable-http2](/docs/azure/functionapp/enable-http2)<br>Web App uses the latest HTTP version|
|[azure-keyvault-content-type-for-secret](/docs/azure/keyvault/content-type-for-secret)<br>Key vault Secret should have a content type set|
|[azure-keyvault-ensure-key-expiry](/docs/azure/keyvault/ensure-key-expiry)<br>Ensure that the expiration date is set on all keys|
|[azure-keyvault-ensure-secret-expiry](/docs/azure/keyvault/ensure-secret-expiry)<br>Key Vault Secret should have an expiration date set|
|[azure-keyvault-no-purge](/docs/azure/keyvault/no-purge)<br>Key vault should have purge protection enabled|
|[azure-keyvault-specify-network-acl](/docs/azure/keyvault/specify-network-acl)<br>Key vault should have the network acl block specified|
|[azure-monitor-activity-log-retention-set](/docs/azure/monitor/activity-log-retention-set)<br>Ensure the activity retention log is set to at least a year|
|[azure-monitor-capture-all-activities](/docs/azure/monitor/capture-all-activities)<br>Ensure log profile captures all activities|
|[azure-monitor-capture-all-regions](/docs/azure/monitor/capture-all-regions)<br>Ensure activitys are captured for all locations|
|[azure-mssql-all-threat-alerts-enabled](/docs/azure/mssql/all-threat-alerts-enabled)<br>No threat detections are set|
|[azure-mssql-threat-alert-email-set](/docs/azure/mssql/threat-alert-email-set)<br>At least one email address is set for threat alerts|
|[azure-mssql-threat-alert-email-to-owner](/docs/azure/mssql/threat-alert-email-to-owner)<br>Security threat alerts go to subcription owners and co-administrators|
|[azure-network-disable-rdp-from-internet](/docs/azure/network/disable-rdp-from-internet)<br>RDP access should not be accessible from the Internet, should be blocked on port 3389|
|[azure-network-no-public-egress](/docs/azure/network/no-public-egress)<br>An outbound network security rule allows traffic to /0.|
|[azure-network-no-public-ingress](/docs/azure/network/no-public-ingress)<br>An inbound network security rule allows traffic from /0.|
|[azure-network-retention-policy-set](/docs/azure/network/retention-policy-set)<br>Retention policy for flow logs should be enabled and set to greater than 90 days|
|[azure-network-ssh-blocked-from-internet](/docs/azure/network/ssh-blocked-from-internet)<br>SSH access should not be accessible from the Internet, should be blocked on port 22|
|[azure-security-center-alert-on-severe-notifications](/docs/azure/security-center/alert-on-severe-notifications)<br>Send notification emails for high severity alerts|
|[azure-security-center-defender-on-appservices](/docs/azure/security-center/defender-on-appservices)<br>Ensure Azure Defender is set to On for container registries|
|[azure-security-center-defender-on-container-registry](/docs/azure/security-center/defender-on-container-registry)<br>Ensure Azure Defender is set to On for container registries|
|[azure-security-center-defender-on-keyvault](/docs/azure/security-center/defender-on-keyvault)<br>Ensure Azure Defender is set to On for key vaults|
|[azure-security-center-defender-on-kubernetes](/docs/azure/security-center/defender-on-kubernetes)<br>Ensure Azure Defender is set to On for Kubernetes|
|[azure-security-center-defender-on-servers](/docs/azure/security-center/defender-on-servers)<br>Ensure Azure Defender is set to On for Servers|
|[azure-security-center-defender-on-sql-servers](/docs/azure/security-center/defender-on-sql-servers)<br>Ensure Azure Defender is set to On for SQL Servers|
|[azure-security-center-defender-on-sql-servers-vms](/docs/azure/security-center/defender-on-sql-servers-vms)<br>Ensure Azure Defender is set to On for Sql Server on Machines|
|[azure-security-center-defender-on-storage](/docs/azure/security-center/defender-on-storage)<br>Ensure Azure Defender is set to On for storage accounts|
|[azure-security-center-enable-standard-subscription](/docs/azure/security-center/enable-standard-subscription)<br>Enable the standard security center subscription tier|
|[azure-security-center-set-required-contact-details](/docs/azure/security-center/set-required-contact-details)<br>The required contact details should be set for security center|
|[azure-storage-allow-microsoft-service-bypass](/docs/azure/storage/allow-microsoft-service-bypass)<br>Trusted Microsoft Services should have bypass access to Storage accounts|
|[azure-storage-container-activity-logs-not-public](/docs/azure/storage/container-activity-logs-not-public)<br>Ensure public access level for Blob Containers is set to private|
|[azure-storage-default-action-deny](/docs/azure/storage/default-action-deny)<br>The default action on Storage account network rules should be set to deny|
|[azure-storage-enforce-https](/docs/azure/storage/enforce-https)<br>Storage accounts should be configured to only accept transfers that are over secure connections|
|[azure-storage-no-public-access](/docs/azure/storage/no-public-access)<br>Storage containers in blob storage mode should not have public access|
|[azure-storage-queue-services-logging-enabled](/docs/azure/storage/queue-services-logging-enabled)<br>When using Queue Services for a storage account, logging should be enabled.|
|[azure-storage-use-secure-tls-policy](/docs/azure/storage/use-secure-tls-policy)<br>The minimum TLS version for Storage Accounts should be TLS1_2|
|[azure-synapse-virtual-network-enabled](/docs/azure/synapse/virtual-network-enabled)<br>Synapse Workspace should have managed virtual network enabled, the default is disabled.|
