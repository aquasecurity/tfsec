| ID | Provider | Service | Description|
|-|-|-|-|
| aws-s3-no-public-access-with-acl | aws | s3 | S3 Bucket has an ACL defined which allows public access. |
| aws-s3-enable-bucket-logging | aws | s3 | S3 Bucket does not have logging enabled. |
| aws-rds-no-classic-resources | aws | rds | AWS Classic resource usage. |
| aws-elbv2-http-not-used | aws | elbv2 | Use of plain HTTP. |
| aws-elbv2-alb-not-public | aws | elbv2 | Load balancer is exposed to the internet. |
| aws-vpc-no-public-ingress-sgr | aws | vpc | An ingress security group rule allows traffic from /0. |
| aws-vpc-no-public-egress-sgr | aws | vpc | An egress security group rule allows traffic to /0. |
| aws-vpc-no-public-ingress-sg | aws | vpc | An inline ingress security group rule allows traffic from /0. |
| aws-vpc-no-public-egress-sg | aws | vpc | An inline egress security group rule allows traffic to /0. |
| aws-vpc-use-secure-tls-policy | aws | vpc | An outdated SSL policy is in use by a load balancer. |
| aws-rds-no-public-db-access | aws | rds | A database resource is marked as publicly accessible. |
| aws-autoscaling-no-public-ip | aws | autoscaling | A resource has a public IP address. |
| aws-ecs-no-plaintext-secrets | aws | ecs | Task definition defines sensitive environment variable(s). |
| aws-autoscaling-enable-at-rest-encryption | aws | autoscaling | Launch configuration with unencrypted block device. |
| aws-sqs-enable-queue-encryption | aws | sqs | Unencrypted SQS queue. |
| aws-sns-enable-topic-encryption | aws | sns | Unencrypted SNS topic. |
| aws-s3-enable-bucket-encryption | aws | s3 | Unencrypted S3 bucket. |
| aws-vpc-add-description-to-security-group | aws | vpc | Missing description for security group/security group rule. |
| aws-kms-auto-rotate-keys | aws | kms | A KMS key is not configured to auto-rotate. |
| aws-cloudfront-enforce-https | aws | cloudfront | CloudFront distribution allows unencrypted (HTTP) communications. |
| aws-cloudfront-use-secure-tls-policy | aws | cloudfront | CloudFront distribution uses outdated SSL/TLS protocols. |
| aws-msk-enable-in-transit-encryption | aws | msk | A MSK cluster allows unencrypted data in transit. |
| aws-ecr-enable-image-scans | aws | ecr | ECR repository has image scans disabled. |
| aws-kinesis-enable-in-transit-encryption | aws | kinesis | Kinesis stream is unencrypted. |
| aws-api-gateway-use-secure-tls-policy | aws | api-gateway | API Gateway domain name uses outdated SSL/TLS protocols. |
| aws-elastic-service-enable-domain-encryption | aws | elastic-service | Elasticsearch domain isn't encrypted at rest. |
| aws-elastic-search-enable-in-transit-encryption | aws | elastic-search | Elasticsearch domain uses plaintext traffic for node to node communication. |
| aws-elastic-search-enforce-https | aws | elastic-search | Elasticsearch doesn't enforce HTTPS traffic. |
| aws-elastic-search-use-secure-tls-policy | aws | elastic-search | Elasticsearch domain endpoint is using outdated TLS policy. |
| aws-elastic-search-encrypt-replication-group | aws | elastic-search | Unencrypted Elasticache Replication Group. |
| aws-elasticache-enable-in-transit-encryption | aws | elasticache | Elasticache Replication Group uses unencrypted traffic. |
| aws-iam-no-password-reuse | aws | iam | IAM Password policy should prevent password reuse. |
| aws-iam-set-max-password-age | aws | iam | IAM Password policy should have expiry less than or equal to 90 days. |
| aws-iam-set-minimum-password-length | aws | iam | IAM Password policy should have minimum password length of 14 or more characters. |
| aws-iam-require-symbols-in-passwords | aws | iam | IAM Password policy should have requirement for at least one symbol in the password. |
| aws-iam-require-numbers-in-passwords | aws | iam | IAM Password policy should have requirement for at least one number in the password. |
| aws-iam-require-lowercase-in-passwords | aws | iam | IAM Password policy should have requirement for at least one lowercase character. |
| aws-iam-require-uppercase-in-passwords | aws | iam | IAM Password policy should have requirement for at least one uppercase character. |
| aws-misc-no-exposing-plaintext-credentials | aws | misc | AWS provider has access credentials specified. |
| aws-cloudfront-enable-waf | aws | cloudfront | CloudFront distribution does not have a WAF in front. |
| aws-sqs-no-wildcards-in-policy-documents | aws | sqs | AWS SQS policy document has wildcard action statement. |
| aws-efs-enable-at-rest-encryption | aws | efs | EFS Encryption has not been enabled |
| aws-vpc-no-public-ingress | aws | vpc | An ingress Network ACL rule allows specific ports from /0. |
| aws-vpc-no-excessive-port-access | aws | vpc | An ingress Network ACL rule allows ALL ports. |
| aws-rds-encrypt-cluster-storage-data | aws | rds | There is no encryption specified or encryption is disabled on the RDS Cluster. |
| aws-rds-encrypt-instance-storage-data | aws | rds | RDS encryption has not been enabled at a DB Instance level. |
| aws-rds-enable-performance-insights | aws | rds | Encryption for RDS Performance Insights should be enabled. |
| aws-elastic-search-enable-domain-logging | aws | elastic-search | Domain logging should be enabled for Elastic Search domains |
| aws-lambda-restrict-source-arn | aws | lambda | Ensure that lambda function permission has a source arn specified |
| aws-athena-enable-at-rest-encryption | aws | athena | Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted |
| aws-athena-no-encryption-override | aws | athena | Athena workgroups should enforce configuration to prevent client disabling encryption |
| aws-api-gateway-enable-access-logging | aws | api-gateway | API Gateway stages for V1 and V2 should have access logging enabled |
| aws-ec2-no-secrets-in-user-data | aws | ec2 | User data for EC2 instances must not contain sensitive AWS keys |
| aws-cloudtrail-enable-all-regions | aws | cloudtrail | Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed |
| aws-cloudtrail-enable-log-validation | aws | cloudtrail | Cloudtrail log validation should be enabled to prevent tampering of log data |
| aws-cloudtrail-enable-at-rest-encryption | aws | cloudtrail | Cloudtrail should be encrypted at rest to secure access to sensitive trail data |
| aws-eks-encrypt-secrets | aws | eks | EKS should have the encryption of secrets enabled |
| aws-eks-enable-control-plane-logging | aws | eks | EKS Clusters should have cluster control plane logging turned on |
| aws-eks-no-public-cluster-access-to-cidr | aws | eks | EKS cluster should not have open CIDR range for public access |
| aws-eks-no-public-cluster-access | aws | eks | EKS Clusters should have the public access disabled |
| aws-elastic-search-enable-logging | aws | elastic-search | AWS ES Domain should have logging enabled |
| aws-cloudfront-enable-logging | aws | cloudfront | Cloudfront distribution should have Access Logging configured |
| aws-s3-ignore-public-acls | aws | s3 | S3 Access Block should Ignore Public Acl |
| aws-s3-block-public-acls | aws | s3 | S3 Access block should block public ACL |
| aws-s3-no-public-buckets | aws | s3 | S3 Access block should restrict public bucket to limit access |
| aws-s3-block-public-policy | aws | s3 | S3 Access block should block public policy |
| aws-s3-enable-versioning | aws | s3 | S3 Data should be versioned |
| aws-ecr-enforce-immutable-repository | aws | ecr | ECR images tags shouldn't be mutable. |
| aws-ec2-enforce-http-token-imds | aws | ec2 | aws_instance should activate session tokens for Instance Metadata Service. |
| aws-codebuild-enable-encryption | aws | codebuild | CodeBuild Project artifacts encryption should not be disabled |
| aws-dynamodb-enable-at-rest-encryption | aws | dynamodb | DAX Cluster should always encrypt data at rest |
| aws-vpc-no-default-vpc | aws | vpc | AWS best practice to not use the default VPC for workflows |
| aws-elb-drop-invalid-headers | aws | elb | Load balancers should drop invalid headers |
| aws-workspace-enable-disk-encryption | aws | workspace | Root and user volumes on Workspaces should be encrypted |
| aws-config-aggregate-all-regions | aws | config | Config configuration aggregator should be using all regions for source |
| aws-dynamodb-enable-recovery | aws | dynamodb | Point in time recovery should be enabled to protect DynamoDB table |
| aws-redshift-non-default-vpc-deployment | aws | redshift | Redshift cluster should be deployed into a specific VPC |
| aws-elasticache-enable-backup-retention | aws | elasticache | Redis cluster should have backup retention turned on |
| aws-cloudwatch-log-group-customer-key | aws | cloudwatch | CloudWatch log groups should be encrypted using CMK |
| aws-ecs-enable-container-insight | aws | ecs | ECS clusters should have container insights enabled |
| aws-rds-backup-retention-specified | aws | rds | RDS Cluster and RDS instance should have backup retention longer than default 1 day |
| aws-dynamodb-table-customer-key | aws | dynamodb | DynamoDB tables should use at rest encryption with a Customer Managed Key |
| aws-ecr-repository-customer-key | aws | ecr | ECR Repository should use customer managed keys to allow more control |
| aws-redshift-encryption-customer-key | aws | redshift | Redshift clusters should use at rest encryption |
| aws-ssm-secret-use-customer-key | aws | ssm | Secrets Manager should use customer managed keys |
| aws-ecs-enable-in-transit-encryption | aws | ecs | ECS Task Definitions with EFS volumes should use in-transit encryption |
| aws-iam-block-kms-policy-wildcard | aws | iam | IAM customer managed policies should not allow decryption actions on all KMS keys |
| aws-s3-specify-public-access-block | aws | s3 | S3 buckets should each define an aws_s3_bucket_public_access_block |
| aws-iam-no-policy-wildcards | aws | iam | IAM policy should avoid use of wildcards and instead apply the principle of least privilege |
| azure-network-no-public-ingress | azure | network | An inbound network security rule allows traffic from /0. |
| azure-network-no-public-egress | azure | network | An outbound network security rule allows traffic to /0. |
| azure-compute-enable-disk-encryption | azure | compute | Unencrypted managed disk. |
| azure-datalake-enable-at-rest-encryption | azure | datalake | Unencrypted data lake storage. |
| azure-compute-ssh-authentication | azure | compute | Password authentication in use instead of SSH keys. |
| azure-container-configured-network-policy | azure | container | Ensure AKS cluster has Network Policy configured |
| azure-container-use-rbac-permissions | azure | container | Ensure RBAC is enabled on AKS clusters |
| azure-container-limit-authorized-ips | azure | container | Ensure AKS has an API Server Authorized IP Ranges enabled |
| azure-container-logging | azure | container | Ensure AKS logging to Azure Monitoring is Configured |
| azure-storage-ensure-https | azure | storage | Ensure HTTPS is enabled on Azure Storage Account |
| azure-storage-no-public-access | azure | storage | Storage containers in blob storage mode should not have public access |
| azure-storage-default-action-deny | azure | storage | The default action on Storage account network rules should be set to deny |
| azure-storage-allow-microsoft-service-bypass | azure | storage | Trusted Microsoft Services should have bypass access to Storage accounts |
| azure-storage-enforce-https | azure | storage | Storage accounts should be configured to only accept transfers that are over secure connections |
| azure-storage-use-secure-tls-policy | azure | storage | The minimum TLS version for Storage Accounts should be TLS1_2 |
| azure-storage-queue-services-logging-enabled | azure | storage | When using Queue Services for a storage account, logging should be enabled. |
| azure-network-ssh-blocked-from-internet | azure | network | SSH access should not be accessible from the Internet, should be blocked on port 22 |
| azure-database-enable-audit | azure | database | Auditing should be enabled on Azure SQL Databases |
| azure-database-retention-period-set | azure | database | Database auditing rentention period should be longer than 90 days |
| azure-keyvault-specify-network-acl | azure | keyvault | Key vault should have the network acl block specified |
| azure-keyvault-no-purge | azure | keyvault | Key vault should have purge protection enabled |
| azure-keyvault-content-type-for-secret | azure | keyvault | Key vault Secret should have a content type set |
| azure-keyvault-ensure-secret-expiry | azure | keyvault | Key Vault Secret should have an expiration date set |
| azure-network-disable-rdp-from-internet | azure | network | RDP access should not be accessible from the Internet, should be blocked on port 3389 |
| azure-datafactory-no-public-access | azure | datafactory | Data Factory should have public access disabled, the default is enabled. |
| azure-keyvault-ensure-key-expiry | azure | keyvault | Ensure that the expiration date is set on all keys |
| azure-synapse-virtual-network-enabled | azure | synapse | Synapse Workspace should have managed virtual network enabled, the default is disabled. |
| azure-appservice-enforce-https | azure | appservice | Ensure the Function App can only be accessed via HTTPS. The default is false. |
| azure-functionapp-authentication-enabled | functionapp | Ensure the Function App has authentication enabled. The default is false. |
| azure-securitycenter-defender-on-appservices | securitycenter | Ensure Defender is enabled for AppServices. |
| azure-securitycenter-defender-on-container-registry | securitycenter | Ensure Defender is enabled for ContainerRegistry. |
| azure-securitycenter-defender-on-keyvault | securitycenter | Ensure Defender is enabled for KeyVault. |
| azure-securitycenter-defender-on-kubernetes | securitycenter | Ensure Defender is enabled for Kubernetes. |
| azure-securitycenter-defender-on-servers | securitycenter | Ensure Defender is enabled for VirtualMachines. |
| azure-securitycenter-defender-on-sql-servers | securitycenter | Ensure Defender is enabled for SqlServers. |
| azure-securitycenter-defender-on-sql-servers-vms | securitycenter | Ensure Defender is enabled for SqlServersVirtualMachines. |
| azure-securitycenter-defender-on-storage | securitycenter | Ensure Defender is enabled for StorageAccounts. |
| digitalocean-compute-no-public-ingress | digitalocean | compute | The firewall has an inbound rule with open access |
| digitalocean-compute-no-public-egress | digitalocean | compute | The firewall has an outbound rule with open access |
| digitalocean-droplet-use-ssh-keys | digitalocean | droplet | SSH Keys are the preferred way to connect to your droplet, no keys are supplied |
| digitalocean-loadbalancing-enforce-https | digitalocean | loadbalancing | The load balancer forwarding rule is using an insecure protocol as an entrypoint |
| digitalocean-spaces-acl-no-public-read | digitalocean | spaces | Spaces bucket or bucket object has public read acl set |
| digitalocean-spaces-versioning-enabled | digitalocean | spaces | Spaces buckets should have versioning enabled |
| digitalocean-spaces-disable-force-destroy | digitalocean | spaces | Force destroy is enabled on Spaces bucket which is dangerous |
| google-compute-disk-encryption-customer-keys | google | compute | Encrypted compute disk with unmanaged keys. |
| google-compute-no-public-ingres | google | compute | An inbound firewall rule allows traffic from /0. |
| google-compute-no-public-egress | google | compute | An outbound firewall rule allows traffic to /0. |
| google-gke-use-rbac-permissions | google | gke | Legacy ABAC permissions are enabled. |
| google-gke-node-metadata-security | google | gke | Node metadata value disables metadata concealment. |
| google-gke-metadata-endpoints-disabled | google | gke | Legacy metadata endpoints enabled. |
| google-gke-no-legacy-authentication | google | gke | Legacy client authentication methods utilized. |
| google-gke-enforce-pod-security-policy | google | gke | Pod security policy enforcement not defined. |
| google-gke-node-shielding-enabled | google | gke | Shielded GKE nodes not enabled. |
| google-iam-no-user-granted-permissions | google | iam | IAM granted directly to user. |
| google-gke-use-service-account | google | gke | Checks for service account defined for GKE nodes |
| google-compute-disk-encryption-required | google | compute | The encryption key used to encrypt a compute disk has been specified in plaintext. |
| general-secrets-sensitive-in-variable | general | secrets | Potentially sensitive data stored in "default" value of variable. |
| general-secrets-sensitive-in-local | general | secrets | Potentially sensitive data stored in local value. |
| general-secrets-sensitive-in-attribute | general | secrets | Potentially sensitive data stored in block attribute. |
| general-secrets-sensitive-in-attribute-value | general | secrets | The attribute has potentially sensitive data, passwords, tokens or keys in it |
| general-secrets-no-plaintext-exposure | general | secrets | The plain text has potentially sensitive data, passwords, tokens or keys in it |
| github-repositories-private | github | repositories | Github repository shouldn't be public. |
| oracle-compute-no-public-ip | oracle | compute | Compute instance requests an IP reservation from a public pool |
