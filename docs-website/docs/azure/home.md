---
title: AZURE Checks
permalink: /docs/azure/home/
has_children: true
has_toc: false
---

The included AZURE checks are listed below. For more information about each check, see the link provided.

| Code  | Summary |
|:-------|:-------------|
|[AZU001](/docs/azure/AZU001)|An inbound network security rule allows traffic from `/0`.|
|[AZU002](/docs/azure/AZU002)|An outbound network security rule allows traffic to `/0`.|
|[AZU003](/docs/azure/AZU003)|Unencrypted managed disk.|
|[AZU004](/docs/azure/AZU004)|Unencrypted data lake storage.|
|[AZU005](/docs/azure/AZU005)|Password authentication in use instead of SSH keys.|
|[AZU006](/docs/azure/AZU006)|Ensure AKS cluster has Network Policy configured|
|[AZU007](/docs/azure/AZU007)|Ensure RBAC is enabled on AKS clusters|
|[AZU008](/docs/azure/AZU008)|Ensure AKS has an API Server Authorized IP Ranges enabled|
|[AZU009](/docs/azure/AZU009)|Ensure AKS logging to Azure Monitoring is Configured|
|[AZU010](/docs/azure/AZU010)|Ensure HTTPS is enabled on Azure Storage Account|
|[AZU011](/docs/azure/AZU011)|Storage containers in blob storage mode should not have public access|
|[AZU012](/docs/azure/AZU012)|The default action on Storage account network rules should be set to deny|
|[AZU013](/docs/azure/AZU013)|Trusted Microsoft Services should have bypass access to Storage accounts|
|[AZU014](/docs/azure/AZU014)|Storage accounts should be configured to only accept transfers that are over secure connections|
|[AZU015](/docs/azure/AZU015)|The minimum TLS version for Storage Accounts should be TLS1_2|
|[AZU016](/docs/azure/AZU016)|When using Queue Services for a storage account, logging should be enabled.|
|[AZU017](/docs/azure/AZU017)|SSH access should not be accessible from the Internet, should be blocked on port 22|
|[AZU018](/docs/azure/AZU018)|Auditing should be enabled on Azure SQL Databases|
|[AZU019](/docs/azure/AZU019)|Database auditing rentention period should be longer than 90 days|
|[AZU020](/docs/azure/AZU020)|Key vault should have the network acl block specified|
|[AZU021](/docs/azure/AZU021)|Key vault should have purge protection enabled|
|[AZU022](/docs/azure/AZU022)|Key vault Secret should have a content type set|

