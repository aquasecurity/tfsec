---
title: Google Checks
permalink: /docs/google/home/
has_children: true
has_toc: false
---

The included Google checks are listed below. For more information about each check, see the link provided.

| Checks |
|:------------|
|[google-bigquery-no-public-access](/docs/google/bigquery/no-public-access)<br>BigQuery datasets should only be accessible within the organisation|
|[google-compute-disk-encryption-customer-key](/docs/google/compute/disk-encryption-customer-key)<br>Disks should be encrypted with Customer Supplied Encryption Keys|
|[google-compute-disk-encryption-customer-keys](/docs/google/compute/disk-encryption-customer-keys)<br>Encrypted compute disk with unmanaged keys.|
|[google-compute-disk-encryption-required](/docs/google/compute/disk-encryption-required)<br>The encryption key used to encrypt a compute disk has been specified in plaintext.|
|[google-compute-enable-shielded-vm](/docs/google/compute/enable-shielded-vm)<br>Instances should have Shielded VM enabled|
|[google-compute-enable-vpc-flow-logs](/docs/google/compute/enable-vpc-flow-logs)<br>VPC flow logs should be enabled for all subnets|
|[google-compute-no-default-service-account](/docs/google/compute/no-default-service-account)<br>Instances should not use the default service account|
|[google-compute-no-ip-forwarding](/docs/google/compute/no-ip-forwarding)<br>Instances should not have IP forwarding enabled|
|[google-compute-no-oslogin-override](/docs/google/compute/no-oslogin-override)<br>Instances should not override the project setting for OS Login|
|[google-compute-no-plaintext-disk-keys](/docs/google/compute/no-plaintext-disk-keys)<br>Disk encryption keys should not be provided in plaintext|
|[google-compute-no-plaintext-vm-disk-keys](/docs/google/compute/no-plaintext-vm-disk-keys)<br>VM disk encryption keys should not be provided in plaintext|
|[google-compute-no-project-wide-ssh-keys](/docs/google/compute/no-project-wide-ssh-keys)<br>Disable project-wide SSH keys for all instances|
|[google-compute-no-public-egress](/docs/google/compute/no-public-egress)<br>An outbound firewall rule allows traffic to /0.|
|[google-compute-no-public-ingress](/docs/google/compute/no-public-ingress)<br>An inbound firewall rule allows traffic from /0.|
|[google-compute-no-public-ip](/docs/google/compute/no-public-ip)<br>Instances should not have public IP addresses|
|[google-compute-no-serial-port](/docs/google/compute/no-serial-port)<br>Disable serial port connectivity for all instances|
|[google-compute-project-level-oslogin](/docs/google/compute/project-level-oslogin)<br>OS Login should be enabled at project level|
|[google-compute-use-secure-tls-policy](/docs/google/compute/use-secure-tls-policy)<br>SSL policies should enforce secure versions of TLS|
|[google-compute-vm-disk-encryption-customer-key](/docs/google/compute/vm-disk-encryption-customer-key)<br>VM disks should be encrypted with Customer Supplied Encryption Keys|
|[google-dns-enable-dnssec](/docs/google/dns/enable-dnssec)<br>Cloud DNS should use DNSSEC|
|[google-dns-no-rsa-sha1](/docs/google/dns/no-rsa-sha1)<br>Zone signing should not use RSA SHA1|
|[google-gke-enable-auto-repair](/docs/google/gke/enable-auto-repair)<br>Kubernetes should have 'Automatic repair' enabled|
|[google-gke-enable-auto-upgrade](/docs/google/gke/enable-auto-upgrade)<br>Kubernetes should have 'Automatic upgrade' enabled|
|[google-gke-enable-ip-aliasing](/docs/google/gke/enable-ip-aliasing)<br>Clusters should have IP aliasing enabled|
|[google-gke-enable-master-networks](/docs/google/gke/enable-master-networks)<br>Master authorized networks should be configured on GKE clusters|
|[google-gke-enable-network-policy](/docs/google/gke/enable-network-policy)<br>Network Policy should be enabled on GKE clusters|
|[google-gke-enable-private-cluster](/docs/google/gke/enable-private-cluster)<br>Clusters should be set to private|
|[google-gke-enable-stackdriver-logging](/docs/google/gke/enable-stackdriver-logging)<br>Stackdriver Logging should be enabled|
|[google-gke-enable-stackdriver-monitoring](/docs/google/gke/enable-stackdriver-monitoring)<br>Stackdriver Monitoring should be enabled|
|[google-gke-enforce-pod-security-policy](/docs/google/gke/enforce-pod-security-policy)<br>Pod security policy enforcement not defined.|
|[google-gke-metadata-endpoints-disabled](/docs/google/gke/metadata-endpoints-disabled)<br>Legacy metadata endpoints enabled.|
|[google-gke-no-legacy-auth](/docs/google/gke/no-legacy-auth)<br>Clusters should use client certificates for authentication|
|[google-gke-no-public-control-plane](/docs/google/gke/no-public-control-plane)<br>GKE Control Plane should not be publicly accessible|
|[google-gke-node-metadata-security](/docs/google/gke/node-metadata-security)<br>Node metadata value disables metadata concealment.|
|[google-gke-node-pool-uses-cos](/docs/google/gke/node-pool-uses-cos)<br>Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image|
|[google-gke-node-shielding-enabled](/docs/google/gke/node-shielding-enabled)<br>Shielded GKE nodes not enabled.|
|[google-gke-use-cluster-labels](/docs/google/gke/use-cluster-labels)<br>Clusters should be configured with Labels|
|[google-gke-use-rbac-permissions](/docs/google/gke/use-rbac-permissions)<br>Legacy ABAC permissions are enabled.|
|[google-gke-use-service-account](/docs/google/gke/use-service-account)<br>Checks for service account defined for GKE nodes|
|[google-iam-no-folder-level-default-service-account-assignment](/docs/google/iam/no-folder-level-default-service-account-assignment)<br>Roles should not be assigned to default service accounts|
|[google-iam-no-folder-level-service-account-impersonation](/docs/google/iam/no-folder-level-service-account-impersonation)<br>Users should not be granted service account access at the folder level|
|[google-iam-no-org-level-default-service-account-assignment](/docs/google/iam/no-org-level-default-service-account-assignment)<br>Roles should not be assigned to default service accounts|
|[google-iam-no-org-level-service-account-impersonation](/docs/google/iam/no-org-level-service-account-impersonation)<br>Users should not be granted service account access at the organization level|
|[google-iam-no-privileged-service-accounts](/docs/google/iam/no-privileged-service-accounts)<br>Service accounts should not have roles assigned with excessive privileges|
|[google-iam-no-project-level-default-service-account-assignment](/docs/google/iam/no-project-level-default-service-account-assignment)<br>Roles should not be assigned to default service accounts|
|[google-iam-no-project-level-service-account-impersonation](/docs/google/iam/no-project-level-service-account-impersonation)<br>Users should not be granted service account access at the project level|
|[google-iam-no-user-granted-permissions](/docs/google/iam/no-user-granted-permissions)<br>IAM granted directly to user.|
|[google-kms-rotate-kms-keys](/docs/google/kms/rotate-kms-keys)<br>KMS keys should be rotated at least every 90 days|
|[google-project-no-default-network](/docs/google/project/no-default-network)<br>Default network should not be created at project level|
|[google-sql-enable-backup](/docs/google/sql/enable-backup)<br>Enable automated backups to recover from data-loss|
|[google-sql-enable-pg-temp-file-logging](/docs/google/sql/enable-pg-temp-file-logging)<br>Temporary file logging should be enabled for all temporary files.|
|[google-sql-encrypt-in-transit-data](/docs/google/sql/encrypt-in-transit-data)<br>SSL connections to a SQL database instance should be enforced.|
|[google-sql-mysql-no-local-infile](/docs/google/sql/mysql-no-local-infile)<br>Disable local_infile setting in MySQL|
|[google-sql-no-contained-db-auth](/docs/google/sql/no-contained-db-auth)<br>Contained database authentication should be disabled|
|[google-sql-no-cross-db-ownership-chaining](/docs/google/sql/no-cross-db-ownership-chaining)<br>Cross-database ownership chaining should be disabled|
|[google-sql-no-public-access](/docs/google/sql/no-public-access)<br>Ensure that Cloud SQL Database Instances are not publicly exposed|
|[google-sql-pg-log-checkpoints](/docs/google/sql/pg-log-checkpoints)<br>Ensure that logging of checkpoints is enabled.|
|[google-sql-pg-log-connections](/docs/google/sql/pg-log-connections)<br>Ensure that logging of connections is enabled.|
|[google-sql-pg-log-disconnections](/docs/google/sql/pg-log-disconnections)<br>Ensure that logging of disconnections is enabled.|
|[google-sql-pg-log-errors](/docs/google/sql/pg-log-errors)<br>Ensure that Postgres errors are logged|
|[google-sql-pg-log-lock-waits](/docs/google/sql/pg-log-lock-waits)<br>Ensure that logging of lock waits is enabled.|
|[google-sql-pg-no-min-statement-logging](/docs/google/sql/pg-no-min-statement-logging)<br>Ensure that logging of long statements is disabled.|
|[google-storage-enable-ubla](/docs/google/storage/enable-ubla)<br>Ensure that Cloud Storage buckets have uniform bucket-level access enabled|
|[google-storage-no-public-access](/docs/google/storage/no-public-access)<br>Ensure that Cloud Storage bucket is not anonymously or publicly accessible.|
