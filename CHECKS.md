
# Checks

The checks listed below have been implemented, for more information about each check, see the wiki link provided.

| Code | Provider | Description | Wiki link |
|------|----------|-------------|-----------|
|AWS001|aws|S3 Bucket has an ACL defined which allows public access.|[AWS001 Wiki](https://github.com/tfsec/tfsec/wiki/AWS001)|
|AWS002|aws|S3 Bucket does not have logging enabled.|[AWS002 Wiki](https://github.com/tfsec/tfsec/wiki/AWS002)|
|AWS003|aws|AWS Classic resource usage.|[AWS003 Wiki](https://github.com/tfsec/tfsec/wiki/AWS003)|
|AWS004|aws|Use of plain HTTP.|[AWS004 Wiki](https://github.com/tfsec/tfsec/wiki/AWS004)|
|AWS005|aws|Load balancer is exposed to the internet.|[AWS005 Wiki](https://github.com/tfsec/tfsec/wiki/AWS005)|
|AWS006|aws|An ingress security group rule allows traffic from `/0`.|[AWS006 Wiki](https://github.com/tfsec/tfsec/wiki/AWS006)|
|AWS007|aws|An egress security group rule allows traffic to `/0`.|[AWS007 Wiki](https://github.com/tfsec/tfsec/wiki/AWS007)|
|AWS008|aws|An inline ingress security group rule allows traffic from `/0`.|[AWS008 Wiki](https://github.com/tfsec/tfsec/wiki/AWS008)|
|AWS009|aws|An inline egress security group rule allows traffic to `/0`.|[AWS009 Wiki](https://github.com/tfsec/tfsec/wiki/AWS009)|
|AWS010|aws|An outdated SSL policy is in use by a load balancer.|[AWS010 Wiki](https://github.com/tfsec/tfsec/wiki/AWS010)|
|AWS011|aws|A resource is marked as publicly accessible.|[AWS011 Wiki](https://github.com/tfsec/tfsec/wiki/AWS011)|
|AWS012|aws|A resource has a public IP address.|[AWS012 Wiki](https://github.com/tfsec/tfsec/wiki/AWS012)|
|AWS013|aws|Task definition defines sensitive environment variable(s).|[AWS013 Wiki](https://github.com/tfsec/tfsec/wiki/AWS013)|
|AWS014|aws|Launch configuration with unencrypted block device.|[AWS014 Wiki](https://github.com/tfsec/tfsec/wiki/AWS014)|
|AWS015|aws|Unencrypted SQS queue.|[AWS015 Wiki](https://github.com/tfsec/tfsec/wiki/AWS015)|
|AWS016|aws|Unencrypted SNS topic.|[AWS016 Wiki](https://github.com/tfsec/tfsec/wiki/AWS016)|
|AWS017|aws|Unencrypted S3 bucket.|[AWS017 Wiki](https://github.com/tfsec/tfsec/wiki/AWS017)|
|AWS018|aws|Missing description for security group/security group rule.|[AWS018 Wiki](https://github.com/tfsec/tfsec/wiki/AWS018)|
|AWS019|aws|A KMS key is not configured to auto-rotate.|[AWS019 Wiki](https://github.com/tfsec/tfsec/wiki/AWS019)|
|AWS020|aws|CloudFront distribution allows unencrypted (HTTP) communications.|[AWS020 Wiki](https://github.com/tfsec/tfsec/wiki/AWS020)|
|AWS021|aws|CloudFront distribution uses outdated SSL/TSL protocols.|[AWS021 Wiki](https://github.com/tfsec/tfsec/wiki/AWS021)|
|AWS022|aws|A MSK cluster allows unencrypted data in transit.|[AWS022 Wiki](https://github.com/tfsec/tfsec/wiki/AWS022)|
|AWS023|aws|ECR repository has image scans disabled.|[AWS023 Wiki](https://github.com/tfsec/tfsec/wiki/AWS023)|
|AWS024|aws|Kinesis stream is unencrypted.|[AWS024 Wiki](https://github.com/tfsec/tfsec/wiki/AWS024)|
|AWS025|aws|API Gateway domain name uses outdated SSL/TLS protocols.|[AWS025 Wiki](https://github.com/tfsec/tfsec/wiki/AWS025)|
|AWS031|aws|Elasticsearch domain isn't encrypted at rest.|[AWS031 Wiki](https://github.com/tfsec/tfsec/wiki/AWS031)|
|AWS032|aws|Elasticsearch domain uses plaintext traffic for node to node communication.|[AWS032 Wiki](https://github.com/tfsec/tfsec/wiki/AWS032)|
|AWS033|aws|Elasticsearch doesn't enforce HTTPS traffic.|[AWS033 Wiki](https://github.com/tfsec/tfsec/wiki/AWS033)|
|AWS034|aws|Elasticsearch domain endpoint is using outdated TLS policy.|[AWS034 Wiki](https://github.com/tfsec/tfsec/wiki/AWS034)|
|AWS035|aws|Unencrypted Elasticache Replication Group.|[AWS035 Wiki](https://github.com/tfsec/tfsec/wiki/AWS035)|
|AWS036|aws|Elasticache Replication Group uses unencrypted traffic.|[AWS036 Wiki](https://github.com/tfsec/tfsec/wiki/AWS036)|
|AWS037|aws|IAM Password policy should prevent password reuse.|[AWS037 Wiki](https://github.com/tfsec/tfsec/wiki/AWS037)|
|AWS038|aws|IAM Password policy should have expiry greater than or equal to 90 days.|[AWS038 Wiki](https://github.com/tfsec/tfsec/wiki/AWS038)|
|AWS039|aws|IAM Password policy should have minimum password length of 14 or more characters.|[AWS039 Wiki](https://github.com/tfsec/tfsec/wiki/AWS039)|
|AWS040|aws|IAM Password policy should have requirement for at least one symbol in the password.|[AWS040 Wiki](https://github.com/tfsec/tfsec/wiki/AWS040)|
|AWS041|aws|IAM Password policy should have requirement for at least one number in the password.|[AWS041 Wiki](https://github.com/tfsec/tfsec/wiki/AWS041)|
|AWS042|aws|IAM Password policy should have requirement for at least one lowercase character.|[AWS042 Wiki](https://github.com/tfsec/tfsec/wiki/AWS042)|
|AWS043|aws|IAM Password policy should have requirement for at least one uppercase character.|[AWS043 Wiki](https://github.com/tfsec/tfsec/wiki/AWS043)|
|AWS044|aws|AWS provider has access credentials specified.|[AWS044 Wiki](https://github.com/tfsec/tfsec/wiki/AWS044)|
|AWS045|aws|CloudFront distribution does not have a WAF in front.|[AWS045 Wiki](https://github.com/tfsec/tfsec/wiki/AWS045)|
|AWS046|aws|AWS IAM policy document has wildcard action statement.|[AWS046 Wiki](https://github.com/tfsec/tfsec/wiki/AWS046)|
|AZU001|azurerm|An inbound network security rule allows traffic from `/0`.|[AZU001 Wiki](https://github.com/tfsec/tfsec/wiki/AZU001)|
|AZU002|azurerm|An outbound network security rule allows traffic to `/0`.|[AZU002 Wiki](https://github.com/tfsec/tfsec/wiki/AZU002)|
|AZU003|azurerm|Unencrypted managed disk.|[AZU003 Wiki](https://github.com/tfsec/tfsec/wiki/AZU003)|
|AZU004|azurerm|Unencrypted data lake store.|[AZU004 Wiki](https://github.com/tfsec/tfsec/wiki/AZU004)|
|AZU005|azurerm|Password authentication in use instead of SSH keys.|[AZU005 Wiki](https://github.com/tfsec/tfsec/wiki/AZU005)|
|GCP001|google|Unencrypted compute disk.|[GCP001 Wiki](https://github.com/tfsec/tfsec/wiki/GCP001)|
|GCP002|google|Unencrypted storage bucket.|[GCP002 Wiki](https://github.com/tfsec/tfsec/wiki/GCP002)|
|GCP003|google|An inbound firewall rule allows traffic from `/0`.|[GCP003 Wiki](https://github.com/tfsec/tfsec/wiki/GCP003)|
|GCP004|google|An outbound firewall rule allows traffic to `/0`.|[GCP004 Wiki](https://github.com/tfsec/tfsec/wiki/GCP004)|
|GCP005|google|Legacy ABAC permissions are enabled.|[GCP005 Wiki](https://github.com/tfsec/tfsec/wiki/GCP005)|
|GCP006|google|Node metadata value disables metadata concealment.|[GCP006 Wiki](https://github.com/tfsec/tfsec/wiki/GCP006)|
|GCP007|google|Legacy metadata endpoints enabled.|[GCP007 Wiki](https://github.com/tfsec/tfsec/wiki/GCP007)|
|GCP008|google|Legacy client authentication methods utilized.|[GCP008 Wiki](https://github.com/tfsec/tfsec/wiki/GCP008)|
|GCP009|google|Pod security policy enforcement not defined.|[GCP009 Wiki](https://github.com/tfsec/tfsec/wiki/GCP009)|
|GCP010|google|Shielded GKE nodes not enabled.|[GCP010 Wiki](https://github.com/tfsec/tfsec/wiki/GCP010)|
|GCP011|google|IAM granted directly to user.|[GCP011 Wiki](https://github.com/tfsec/tfsec/wiki/GCP011)|
|GEN001|*|Potentially sensitive data stored in "default" value of variable.|[GEN001 Wiki](https://github.com/tfsec/tfsec/wiki/GEN001)|
|GEN002|*|Potentially sensitive data stored in local value.|[GEN002 Wiki](https://github.com/tfsec/tfsec/wiki/GEN002)|
|GEN003|*|Potentially sensitive data stored in block attribute.|[GEN003 Wiki](https://github.com/tfsec/tfsec/wiki/GEN003)|

