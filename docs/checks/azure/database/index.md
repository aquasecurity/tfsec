---
title: database
---

# database

## Checks


- [all-threat-alerts-enabled](all-threat-alerts-enabled) No threat detections are set

- [enable-audit](enable-audit) Auditing should be enabled on Azure SQL Databases

- [enable-ssl-enforcement](enable-ssl-enforcement) SSL should be enforced on database connections where applicable

- [no-public-access](no-public-access) Ensure databases are not publicly accessible

- [no-public-firewall-access](no-public-firewall-access) Ensure database firewalls do not permit public access

- [postgres-configuration-connection-throttling](postgres-configuration-connection-throttling) Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server

- [postgres-configuration-log-checkpoints](postgres-configuration-log-checkpoints) Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server

- [postgres-configuration-log-connections](postgres-configuration-log-connections) Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server

- [retention-period-set](retention-period-set) Database auditing rentention period should be longer than 90 days

- [secure-tls-policy](secure-tls-policy) Databases should have the minimum TLS set for connections

- [threat-alert-email-set](threat-alert-email-set) At least one email address is set for threat alerts

- [threat-alert-email-to-owner](threat-alert-email-to-owner) Security threat alerts go to subscription owners and co-administrators



