---
title: AWS Checks
permalink: /docs/aws/home/
has_children: true
has_toc: false
---

The included AWS checks are listed below. For more information about each check, see the link provided.

| Checks |
|:------------|
|[aws-api-gateway-enable-access-logging](/docs/aws/api-gateway/enable-access-logging)<br>API Gateway stages for V1 and V2 should have access logging enabled|
|[aws-api-gateway-enable-cache-encryption](/docs/aws/api-gateway/enable-cache-encryption)<br>API Gateway must have cache enabled|
|[aws-api-gateway-enable-tracing](/docs/aws/api-gateway/enable-tracing)<br>API Gateway must have X-Ray tracing enabled|
|[aws-api-gateway-no-public-access](/docs/aws/api-gateway/no-public-access)<br>No public access to API Gateway methods|
|[aws-api-gateway-use-secure-tls-policy](/docs/aws/api-gateway/use-secure-tls-policy)<br>API Gateway domain name uses outdated SSL/TLS protocols.|
|[aws-athena-enable-at-rest-encryption](/docs/aws/athena/enable-at-rest-encryption)<br>Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted|
|[aws-athena-no-encryption-override](/docs/aws/athena/no-encryption-override)<br>Athena workgroups should enforce configuration to prevent client disabling encryption|
|[aws-autoscaling-enable-at-rest-encryption](/docs/aws/autoscaling/enable-at-rest-encryption)<br>Launch configuration with unencrypted block device.|
|[aws-autoscaling-no-public-ip](/docs/aws/autoscaling/no-public-ip)<br>A resource has a public IP address.|
|[aws-cloudfront-enable-logging](/docs/aws/cloudfront/enable-logging)<br>Cloudfront distribution should have Access Logging configured|
|[aws-cloudfront-enable-waf](/docs/aws/cloudfront/enable-waf)<br>CloudFront distribution does not have a WAF in front.|
|[aws-cloudfront-enforce-https](/docs/aws/cloudfront/enforce-https)<br>CloudFront distribution allows unencrypted (HTTP) communications.|
|[aws-cloudfront-use-secure-tls-policy](/docs/aws/cloudfront/use-secure-tls-policy)<br>CloudFront distribution uses outdated SSL/TLS protocols.|
|[aws-cloudtrail-enable-all-regions](/docs/aws/cloudtrail/enable-all-regions)<br>Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed|
|[aws-cloudtrail-enable-at-rest-encryption](/docs/aws/cloudtrail/enable-at-rest-encryption)<br>Cloudtrail should be encrypted at rest to secure access to sensitive trail data|
|[aws-cloudtrail-enable-log-validation](/docs/aws/cloudtrail/enable-log-validation)<br>Cloudtrail log validation should be enabled to prevent tampering of log data|
|[aws-cloudwatch-log-group-customer-key](/docs/aws/cloudwatch/log-group-customer-key)<br>CloudWatch log groups should be encrypted using CMK|
|[aws-codebuild-enable-encryption](/docs/aws/codebuild/enable-encryption)<br>CodeBuild Project artifacts encryption should not be disabled|
|[aws-config-aggregate-all-regions](/docs/aws/config/aggregate-all-regions)<br>Config configuration aggregator should be using all regions for source|
|[aws-documentdb-enable-log-export](/docs/aws/documentdb/enable-log-export)<br>DocumentDB logs export should be enabled|
|[aws-documentdb-enable-storage-encryption](/docs/aws/documentdb/enable-storage-encryption)<br>DocumentDB storage must be encrypted|
|[aws-documentdb-encryption-customer-key](/docs/aws/documentdb/encryption-customer-key)<br>DocumentDB encryption should use Customer Managed Keys|
|[aws-dynamodb-enable-at-rest-encryption](/docs/aws/dynamodb/enable-at-rest-encryption)<br>DAX Cluster should always encrypt data at rest|
|[aws-dynamodb-enable-recovery](/docs/aws/dynamodb/enable-recovery)<br>Point in time recovery should be enabled to protect DynamoDB table|
|[aws-dynamodb-table-customer-key](/docs/aws/dynamodb/table-customer-key)<br>DynamoDB tables should use at rest encryption with a Customer Managed Key|
|[aws-ebs-enable-volume-encryption](/docs/aws/ebs/enable-volume-encryption)<br>EBS volumes must be encrypted|
|[aws-ebs-encryption-customer-key](/docs/aws/ebs/encryption-customer-key)<br>EBS volume encryption should use Customer Managed Keys|
|[aws-ec2-enforce-http-token-imds](/docs/aws/ec2/enforce-http-token-imds)<br>aws_instance should activate session tokens for Instance Metadata Service.|
|[aws-ec2-no-secrets-in-user-data](/docs/aws/ec2/no-secrets-in-user-data)<br>User data for EC2 instances must not contain sensitive AWS keys|
|[aws-ecr-enable-image-scans](/docs/aws/ecr/enable-image-scans)<br>ECR repository has image scans disabled.|
|[aws-ecr-enforce-immutable-repository](/docs/aws/ecr/enforce-immutable-repository)<br>ECR images tags shouldn't be mutable.|
|[aws-ecr-no-public-access](/docs/aws/ecr/no-public-access)<br>ECR repository policy must block public access|
|[aws-ecr-repository-customer-key](/docs/aws/ecr/repository-customer-key)<br>ECR Repository should use customer managed keys to allow more control|
|[aws-ecs-enable-container-insight](/docs/aws/ecs/enable-container-insight)<br>ECS clusters should have container insights enabled|
|[aws-ecs-enable-in-transit-encryption](/docs/aws/ecs/enable-in-transit-encryption)<br>ECS Task Definitions with EFS volumes should use in-transit encryption|
|[aws-ecs-no-plaintext-secrets](/docs/aws/ecs/no-plaintext-secrets)<br>Task definition defines sensitive environment variable(s).|
|[aws-efs-enable-at-rest-encryption](/docs/aws/efs/enable-at-rest-encryption)<br>EFS Encryption has not been enabled|
|[aws-eks-enable-control-plane-logging](/docs/aws/eks/enable-control-plane-logging)<br>EKS Clusters should have cluster control plane logging turned on|
|[aws-eks-encrypt-secrets](/docs/aws/eks/encrypt-secrets)<br>EKS should have the encryption of secrets enabled|
|[aws-eks-no-public-cluster-access](/docs/aws/eks/no-public-cluster-access)<br>EKS Clusters should have the public access disabled|
|[aws-eks-no-public-cluster-access-to-cidr](/docs/aws/eks/no-public-cluster-access-to-cidr)<br>EKS cluster should not have open CIDR range for public access|
|[aws-elastic-search-enable-domain-logging](/docs/aws/elastic-search/enable-domain-logging)<br>Domain logging should be enabled for Elastic Search domains|
|[aws-elastic-search-enable-in-transit-encryption](/docs/aws/elastic-search/enable-in-transit-encryption)<br>Elasticsearch domain uses plaintext traffic for node to node communication.|
|[aws-elastic-search-enable-logging](/docs/aws/elastic-search/enable-logging)<br>AWS ES Domain should have logging enabled|
|[aws-elastic-search-encrypt-replication-group](/docs/aws/elastic-search/encrypt-replication-group)<br>Unencrypted Elasticache Replication Group.|
|[aws-elastic-search-enforce-https](/docs/aws/elastic-search/enforce-https)<br>Elasticsearch doesn't enforce HTTPS traffic.|
|[aws-elastic-search-use-secure-tls-policy](/docs/aws/elastic-search/use-secure-tls-policy)<br>Elasticsearch domain endpoint is using outdated TLS policy.|
|[aws-elastic-service-enable-domain-encryption](/docs/aws/elastic-service/enable-domain-encryption)<br>Elasticsearch domain isn't encrypted at rest.|
|[aws-elasticache-add-description-for-security-group](/docs/aws/elasticache/add-description-for-security-group)<br>Missing description for security group/security group rule.|
|[aws-elasticache-enable-backup-retention](/docs/aws/elasticache/enable-backup-retention)<br>Redis cluster should have backup retention turned on|
|[aws-elasticache-enable-in-transit-encryption](/docs/aws/elasticache/enable-in-transit-encryption)<br>Elasticache Replication Group uses unencrypted traffic.|
|[aws-elb-drop-invalid-headers](/docs/aws/elb/drop-invalid-headers)<br>Load balancers should drop invalid headers|
|[aws-elbv2-alb-not-public](/docs/aws/elbv2/alb-not-public)<br>Load balancer is exposed to the internet.|
|[aws-elbv2-http-not-used](/docs/aws/elbv2/http-not-used)<br>Use of plain HTTP.|
|[aws-iam-block-kms-policy-wildcard](/docs/aws/iam/block-kms-policy-wildcard)<br>IAM customer managed policies should not allow decryption actions on all KMS keys|
|[aws-iam-no-password-reuse](/docs/aws/iam/no-password-reuse)<br>IAM Password policy should prevent password reuse.|
|[aws-iam-no-policy-wildcards](/docs/aws/iam/no-policy-wildcards)<br>IAM policy should avoid use of wildcards and instead apply the principle of least privilege|
|[aws-iam-require-lowercase-in-passwords](/docs/aws/iam/require-lowercase-in-passwords)<br>IAM Password policy should have requirement for at least one lowercase character.|
|[aws-iam-require-numbers-in-passwords](/docs/aws/iam/require-numbers-in-passwords)<br>IAM Password policy should have requirement for at least one number in the password.|
|[aws-iam-require-symbols-in-passwords](/docs/aws/iam/require-symbols-in-passwords)<br>IAM Password policy should have requirement for at least one symbol in the password.|
|[aws-iam-require-uppercase-in-passwords](/docs/aws/iam/require-uppercase-in-passwords)<br>IAM Password policy should have requirement for at least one uppercase character.|
|[aws-iam-set-max-password-age](/docs/aws/iam/set-max-password-age)<br>IAM Password policy should have expiry less than or equal to 90 days.|
|[aws-iam-set-minimum-password-length](/docs/aws/iam/set-minimum-password-length)<br>IAM Password policy should have minimum password length of 14 or more characters.|
|[aws-kinesis-enable-in-transit-encryption](/docs/aws/kinesis/enable-in-transit-encryption)<br>Kinesis stream is unencrypted.|
|[aws-kms-auto-rotate-keys](/docs/aws/kms/auto-rotate-keys)<br>A KMS key is not configured to auto-rotate.|
|[aws-lambda-enable-tracing](/docs/aws/lambda/enable-tracing)<br>Lambda functions should have X-Ray tracing enabled|
|[aws-lambda-restrict-source-arn](/docs/aws/lambda/restrict-source-arn)<br>Ensure that lambda function permission has a source arn specified|
|[aws-launch-no-sensitive-info](/docs/aws/launch/no-sensitive-info)<br>Ensure all data stored in the Launch configuration EBS is securely encrypted|
|[aws-misc-no-exposing-plaintext-credentials](/docs/aws/misc/no-exposing-plaintext-credentials)<br>AWS provider has access credentials specified.|
|[aws-mq-enable-audit-logging](/docs/aws/mq/enable-audit-logging)<br>MQ Broker should have audit logging enabled|
|[aws-mq-enable-general-logging](/docs/aws/mq/enable-general-logging)<br>MQ Broker should have general logging enabled|
|[aws-mq-no-public-access](/docs/aws/mq/no-public-access)<br>Ensure MQ Broker is not publicly exposed|
|[aws-msk-enable-in-transit-encryption](/docs/aws/msk/enable-in-transit-encryption)<br>A MSK cluster allows unencrypted data in transit.|
|[aws-msk-enable-logging](/docs/aws/msk/enable-logging)<br>Ensure MSK Cluster logging is enabled|
|[aws-neptune-enable-log-export](/docs/aws/neptune/enable-log-export)<br>Nepture logs export should be enabled|
|[aws-neptune-enable-storage-encryption](/docs/aws/neptune/enable-storage-encryption)<br>Neptune storage must be encrypted at rest|
|[aws-rds-backup-retention-specified](/docs/aws/rds/backup-retention-specified)<br>RDS Cluster and RDS instance should have backup retention longer than default 1 day|
|[aws-rds-enable-performance-insights](/docs/aws/rds/enable-performance-insights)<br>Encryption for RDS Performance Insights should be enabled.|
|[aws-rds-encrypt-cluster-storage-data](/docs/aws/rds/encrypt-cluster-storage-data)<br>There is no encryption specified or encryption is disabled on the RDS Cluster.|
|[aws-rds-encrypt-instance-storage-data](/docs/aws/rds/encrypt-instance-storage-data)<br>RDS encryption has not been enabled at a DB Instance level.|
|[aws-rds-no-classic-resources](/docs/aws/rds/no-classic-resources)<br>AWS Classic resource usage.|
|[aws-rds-no-public-db-access](/docs/aws/rds/no-public-db-access)<br>A database resource is marked as publicly accessible.|
|[aws-redshift-add-description-to-security-group](/docs/aws/redshift/add-description-to-security-group)<br>Missing description for security group/security group rule.|
|[aws-redshift-encryption-customer-key](/docs/aws/redshift/encryption-customer-key)<br>Redshift clusters should use at rest encryption|
|[aws-redshift-non-default-vpc-deployment](/docs/aws/redshift/non-default-vpc-deployment)<br>Redshift cluster should be deployed into a specific VPC|
|[aws-s3-block-public-acls](/docs/aws/s3/block-public-acls)<br>S3 Access block should block public ACL|
|[aws-s3-block-public-policy](/docs/aws/s3/block-public-policy)<br>S3 Access block should block public policy|
|[aws-s3-enable-bucket-encryption](/docs/aws/s3/enable-bucket-encryption)<br>Unencrypted S3 bucket.|
|[aws-s3-enable-bucket-logging](/docs/aws/s3/enable-bucket-logging)<br>S3 Bucket does not have logging enabled.|
|[aws-s3-enable-versioning](/docs/aws/s3/enable-versioning)<br>S3 Data should be versioned|
|[aws-s3-ignore-public-acls](/docs/aws/s3/ignore-public-acls)<br>S3 Access Block should Ignore Public Acl|
|[aws-s3-no-public-access-with-acl](/docs/aws/s3/no-public-access-with-acl)<br>S3 Bucket has an ACL defined which allows public access.|
|[aws-s3-no-public-buckets](/docs/aws/s3/no-public-buckets)<br>S3 Access block should restrict public bucket to limit access|
|[aws-s3-specify-public-access-block](/docs/aws/s3/specify-public-access-block)<br>S3 buckets should each define an aws_s3_bucket_public_access_block|
|[aws-sns-enable-topic-encryption](/docs/aws/sns/enable-topic-encryption)<br>Unencrypted SNS topic.|
|[aws-sqs-enable-queue-encryption](/docs/aws/sqs/enable-queue-encryption)<br>Unencrypted SQS queue.|
|[aws-sqs-no-wildcards-in-policy-documents](/docs/aws/sqs/no-wildcards-in-policy-documents)<br>AWS SQS policy document has wildcard action statement.|
|[aws-ssm-secret-use-customer-key](/docs/aws/ssm/secret-use-customer-key)<br>Secrets Manager should use customer managed keys|
|[aws-vpc-add-description-to-security-group](/docs/aws/vpc/add-description-to-security-group)<br>Missing description for security group/security group rule.|
|[aws-vpc-disallow-mixed-sgr](/docs/aws/vpc/disallow-mixed-sgr)<br>Ensures that usage of security groups with inline rules and security group rule resources are not mixed.|
|[aws-vpc-no-default-vpc](/docs/aws/vpc/no-default-vpc)<br>AWS best practice to not use the default VPC for workflows|
|[aws-vpc-no-excessive-port-access](/docs/aws/vpc/no-excessive-port-access)<br>An ingress Network ACL rule allows ALL ports.|
|[aws-vpc-no-public-egress-sg](/docs/aws/vpc/no-public-egress-sg)<br>An inline egress security group rule allows traffic to /0.|
|[aws-vpc-no-public-egress-sgr](/docs/aws/vpc/no-public-egress-sgr)<br>An egress security group rule allows traffic to /0.|
|[aws-vpc-no-public-ingress](/docs/aws/vpc/no-public-ingress)<br>An ingress Network ACL rule allows specific ports from /0.|
|[aws-vpc-no-public-ingress-sg](/docs/aws/vpc/no-public-ingress-sg)<br>An inline ingress security group rule allows traffic from /0.|
|[aws-vpc-no-public-ingress-sgr](/docs/aws/vpc/no-public-ingress-sgr)<br>An ingress security group rule allows traffic from /0.|
|[aws-vpc-use-secure-tls-policy](/docs/aws/vpc/use-secure-tls-policy)<br>An outdated SSL policy is in use by a load balancer.|
|[aws-workspace-enable-disk-encryption](/docs/aws/workspace/enable-disk-encryption)<br>Root and user volumes on Workspaces should be encrypted|
